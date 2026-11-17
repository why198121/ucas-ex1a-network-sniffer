import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from .http import inspect_http


def sequence_delta(sequence, reference):
    # 以参考序号为中心进行模 2^32 运算；单方向保留窗口远小于 2^31。
    return ((sequence - reference + 0x80000000) & 0xFFFFFFFF) - 0x80000000


class Reassembly:
    def __init__(self, limit=262144):
        self.reference = None
        self.syn_seen = False
        self.segments = []
        self.limit = limit
        self.stored_bytes = 0
        self.duplicate_bytes = 0
        self.conflict_bytes = 0
        self.limited = False
        self.fin_position = None

    def add(self, sequence, data, syn=False, fin=False):
        payload_sequence = (sequence + int(syn)) & 0xFFFFFFFF
        if self.reference is None:
            self.reference = payload_sequence
        if syn and not self.syn_seen:
            shift = sequence_delta(self.reference, payload_sequence)
            self.segments = [(start + shift, value) for start, value in self.segments]
            if self.fin_position is not None:
                self.fin_position += shift
            self.reference = payload_sequence
            self.syn_seen = True
        start = sequence_delta(payload_sequence, self.reference)
        if fin:
            self.fin_position = start + len(data)
        if not data or self.limited:
            return
        if start < 0 and self.syn_seen:
            self.conflict_bytes += min(len(data), -start)
            data, start = data[-start:], 0
        pieces = [(start, data)]
        # 已观察的字节优先。重传和重叠仅填补尚未观察的区间，冲突单独计数。
        for old_start, old_data in self.segments:
            old_end = old_start + len(old_data)
            remaining = []
            for position, value in pieces:
                ending = position + len(value)
                left, right = max(position, old_start), min(ending, old_end)
                if left >= right:
                    remaining.append((position, value))
                    continue
                new_part = value[left - position:right - position]
                old_part = old_data[left - old_start:right - old_start]
                self.duplicate_bytes += right - left
                self.conflict_bytes += sum(a != b for a, b in zip(new_part, old_part))
                if position < left:
                    remaining.append((position, value[:left - position]))
                if right < ending:
                    remaining.append((right, value[right - position:]))
            pieces = remaining
            if not pieces:
                break
        needed = sum(len(value) for _, value in pieces)
        if self.stored_bytes + needed > self.limit or len(self.segments) + len(pieces) > 4096:
            self.limited = True
            return
        self.stored_bytes += needed
        ordered = sorted(self.segments + pieces)
        merged = []
        for position, value in ordered:
            if not value:
                continue
            if merged and merged[-1][0] + len(merged[-1][1]) == position:
                prior, prefix = merged[-1]
                merged[-1] = (prior, prefix + value)
            else:
                merged.append((position, value))
        self.segments = merged

    def view(self):
        gaps = []
        cursor = 0 if self.syn_seen else (self.segments[0][0] if self.segments else 0)
        for start, value in self.segments:
            if start > cursor:
                gaps.append((cursor, start))
            cursor = max(cursor, start + len(value))
        if self.fin_position is not None and self.fin_position > cursor:
            gaps.append((cursor, self.fin_position))
        contiguous = b""
        if self.segments and (not self.syn_seen or self.segments[0][0] == 0):
            contiguous = self.segments[0][1]
        return {"segments": list(self.segments), "data": contiguous, "gaps": gaps,
                "missing_prefix": not self.syn_seen, "limited": self.limited,
                "duplicate_bytes": self.duplicate_bytes, "conflict_bytes": self.conflict_bytes,
                "incomplete": bool(gaps) or not self.syn_seen or self.limited or bool(self.conflict_bytes),
                "fin_seen": self.fin_position is not None}

    def discard(self):
        self.segments.clear()
        self.stored_bytes = 0
        self.limited = True


@dataclass
class Stream:
    id: int
    key: tuple
    endpoints: tuple
    started: int
    ended: int
    state: str = "MIDSTREAM"
    packets: list = field(default_factory=lambda: [0, 0])
    bytes: list = field(default_factory=lambda: [0, 0])
    payload_bytes: list = field(default_factory=lambda: [0, 0])
    directions: list = field(default_factory=lambda: [Reassembly(), Reassembly()])
    syn_sequences: dict = field(default_factory=dict)
    fin_directions: set = field(default_factory=set)
    events: deque = field(default_factory=lambda: deque(maxlen=256))
    events_dropped: int = 0
    owners: dict = field(default_factory=dict)
    association_statuses: set = field(default_factory=set)
    http: list = field(default_factory=lambda: [[], []])


class StreamManager:
    def __init__(self, max_streams=512, max_bytes=32 * 1024 * 1024, idle_seconds=120):
        self.streams = OrderedDict()
        self.current = {}
        self.next_id = 0
        self.max_streams, self.max_bytes = max_streams, max_bytes
        self.idle_ns = int(idle_seconds * 1_000_000_000)
        self.lock = threading.RLock()
        self.evicted = 0

    def add(self, packet):
        if "tcp" not in packet.fields:
            return
        with self.lock:
            self._add(packet)

    def _add(self, packet):
        source, destination = (packet.src, packet.sport), (packet.dst, packet.dport)
        key = (6 if "ipv6" in packet.fields else 4, *sorted((source, destination)))
        timestamp = packet.raw.timestamp_ns
        flags, sequence = packet.fields["tcp.flags"], packet.fields["tcp.seq"]
        flow = self.streams.get(self.current.get(key))
        new_syn = bool(flags & 2 and not flags & 16)
        new_generation = False
        if flow:
            direction = 0 if source == flow.endpoints[0] else 1
            new_generation = (timestamp - flow.ended > self.idle_ns or
                              new_syn and (flow.state in ("CLOSED", "RESET") or
                                           not flow.syn_sequences or
                                           direction in flow.syn_sequences and flow.syn_sequences[direction] != sequence))
        if flow is None or new_generation:
            flow = Stream(self.next_id, key, (source, destination), timestamp, timestamp)
            self.next_id += 1
            self.streams[flow.id] = flow
            self.current[key] = flow.id
        direction = 0 if source == flow.endpoints[0] else 1
        flow.ended = max(flow.ended, timestamp)
        flow.packets[direction] += 1
        flow.bytes[direction] += packet.raw.wirelen
        flow.payload_bytes[direction] += len(packet.payload)
        packet.stream_id = flow.id
        packet.fields["tcp.stream"] = flow.id
        packet.layers["TCP"]["stream"] = flow.id
        flow.association_statuses.add(packet.process["status"])
        for owner in packet.process.get("owners", []):
            if len(flow.owners) < 64:
                flow.owners[(owner["pid"], owner.get("created"), owner.get("local", ""))] = dict(owner)
        if flags & 2:
            flow.syn_sequences[direction] = sequence
            flow.state = "SYN_ACK" if flags & 16 else "SYN_SENT"
        elif flags & 16 and flow.state in ("SYN_SENT", "SYN_ACK"):
            flow.state = "ESTABLISHED" if len(flow.syn_sequences) == 2 else "PARTIAL_HANDSHAKE"
        flow.directions[direction].add(sequence, packet.payload, bool(flags & 2), bool(flags & 1))
        if flags & 1:
            flow.fin_directions.add(direction)
            flow.state = "CLOSED" if len(flow.fin_directions) == 2 else "HALF_CLOSED"
        if flags & 4:
            flow.state = "RESET"
        event = "/".join(packet.fields["tcp.flag_names"]) if flags & 7 else ("DATA" if packet.payload else "ACK")
        if len(flow.events) == flow.events.maxlen:
            flow.events_dropped += 1
        flow.events.append({"number": packet.raw.number, "timestamp_ns": timestamp, "direction": direction,
                            "event": event, "sequence": sequence, "payload_length": len(packet.payload)})
        views = [buffer.view() for buffer in flow.directions]
        for index in range(2):
            methods = [message["method"] for message in flow.http[1 - index] if "method" in message]
            flow.http[index] = inspect_http(views[index]["data"], closed=views[index]["fin_seen"] and not views[index]["gaps"], request_methods=methods)
        if flow.http[direction] and packet.payload:
            message = flow.http[direction][-1]
            packet.layer("HTTP", message)
            packet.summary = f"HTTP {message.get('method', message.get('status', ''))} {message.get('path', message.get('reason', ''))} · 流 {flow.id} · {message['body_state']}"
        self.streams.move_to_end(flow.id)
        while len(self.streams) > self.max_streams:
            identifier, removed = self.streams.popitem(last=False)
            if self.current.get(removed.key) == identifier:
                del self.current[removed.key]
            self.evicted += 1
        stored = sum(sum(part.stored_bytes for part in item.directions) for item in self.streams.values())
        for item in self.streams.values():
            if stored <= self.max_bytes:
                break
            for part in item.directions:
                stored -= part.stored_bytes
                part.discard()
            item.http = [[], []]

    @staticmethod
    def summary(flow):
        return {"id": flow.id, "endpoints": flow.endpoints, "started": flow.started, "ended": flow.ended,
                "packets": list(flow.packets), "bytes": list(flow.bytes), "payload_bytes": list(flow.payload_bytes),
                "state": flow.state, "owners": list(flow.owners.values()), "association_statuses": sorted(flow.association_statuses)}

    def snapshot(self):
        with self.lock:
            return [self.summary(flow) for flow in self.streams.values()]

    def get(self, identifier):
        with self.lock:
            flow = self.streams.get(identifier)
            if flow is None:
                return None
            result = self.summary(flow)
            result.update(directions=[part.view() for part in flow.directions], events=list(flow.events),
                          events_dropped=flow.events_dropped, http=[list(messages) for messages in flow.http])
            return result
