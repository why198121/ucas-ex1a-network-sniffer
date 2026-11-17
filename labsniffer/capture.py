import logging
import hashlib
import queue
import threading
import time
import uuid
from dataclasses import asdict, replace
from pathlib import Path

from .models import CaptureStats, Packet
from .npcap import Npcap
from .storage import PcapFile, SessionWriter, load_metadata


class CaptureEngine:
    def __init__(self, root, config=None, source=None, parser=None, analyzer=None, process_tracker=None, queue_size=2048):
        if (config is None) == (source is None):
            raise ValueError("必须选择实时网卡或离线文件")
        self.config, self.source = config, source
        self.parser = parser or self.frame_only
        self.analyzer = analyzer
        self.process_tracker = process_tracker
        self.directory = Path(root) / str(uuid.uuid4())
        self.raw_queue = queue.Queue(queue_size)
        self.disk_queue = queue.Queue(queue_size)
        self.gui_queue = queue.Queue(queue_size)
        self.stats = CaptureStats()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.capture_done = threading.Event()
        self.parse_done = threading.Event()
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.error = ""
        self.warnings = []
        self.linktype = None
        self.started_at = 0.0
        self.ended_at = None
        self.threads = []
        self.metadata = None

    @staticmethod
    def frame_only(raw):
        packet = Packet(raw)
        packet.layer("Frame", {"number": raw.number, "caplen": raw.caplen, "len": raw.wirelen,
                               "linktype": raw.linktype, "truncated": raw.caplen < raw.wirelen})
        return packet

    def start(self):
        if self.threads:
            raise RuntimeError("一个采集实例只能启动一次；重新开始需要新建会话")
        self.started_at = time.monotonic()
        for name, task in (("capture", self._capture), ("analysis", self._parse), ("disk", self._write)):
            thread = threading.Thread(target=self._guard, args=(name, task), name=f"lab-{name}", daemon=False)
            self.threads.append(thread)
            thread.start()

    def _guard(self, name, task):
        try:
            task()
        except Exception as error:
            logging.exception("%s 工作线程失败", name)
            with self.lock:
                self.error = f"{name}：{error}"
            self.stop_event.set()
        finally:
            if name == "capture":
                self.ready.set()
                self.capture_done.set()
            elif name == "analysis":
                self.parse_done.set()
            elif name == "disk":
                self.ended_at = time.monotonic()
                self.finished.set()

    def _capture(self):
        if self.source:
            self.metadata = load_metadata(self.source)
            records = 0
            for raw in PcapFile.read(self.source):
                if self.stop_event.is_set():
                    break
                if self.linktype is None:
                    self.linktype = raw.linktype
                    if self.metadata and self.metadata["linktype"] != self.linktype:
                        raise ValueError("进程元数据的链路类型不一致")
                    self.ready.set()
                records += 1
                self._count(raw)
                while not self.stop_event.is_set():
                    try:
                        self.raw_queue.put(raw, timeout=0.05)
                        break
                    except queue.Full:
                        continue
            if self.metadata and not self.stop_event.is_set() and records != self.metadata["packet_count"]:
                raise ValueError("抓包文件与进程元数据的包数不一致")
            return
        api = Npcap()
        with api.open(self.config) as capture:
            self.linktype = capture.linktype
            self.warnings = capture.warnings
            self.ready.set()
            number, last_stats = 0, 0.0
            while not self.stop_event.is_set():
                raw = capture.next_packet(number + 1)
                if raw is None:
                    self.stop_event.wait(0.005)
                else:
                    number += 1
                    self._count(raw)
                    try:
                        self.raw_queue.put_nowait(raw)
                    except queue.Full:
                        with self.lock:
                            self.stats.capture_queue_drops += 1
                if time.monotonic() - last_stats >= 1:
                    self._driver_stats(capture.stats())
                    last_stats = time.monotonic()
            self._driver_stats(capture.stats())

    def _count(self, raw):
        with self.lock:
            self.stats.captured += 1
            self.stats.bytes += raw.caplen
            self.stats.wire_bytes += raw.wirelen

    def _driver_stats(self, values):
        with self.lock:
            for name, value in values.items():
                setattr(self.stats, name, value)

    def _parse(self):
        self.ready.wait()
        while not self.capture_done.is_set() or not self.raw_queue.empty():
            if self.error:
                break
            try:
                raw = self.raw_queue.get(timeout=0.05)
            except queue.Empty:
                continue
            if self.metadata:
                record = self.metadata["packets"][raw.number - 1]
                if (record["timestamp_ns"] != str(raw.timestamp_ns) or record["caplen"] != raw.caplen
                        or record["wirelen"] != raw.wirelen or record["sha256"] != hashlib.sha256(raw.data).hexdigest()):
                    raise ValueError("进程元数据的逐包校验失败")
                raw = replace(raw, number=record["original_number"])
            packet = self.parser(raw)
            if self.metadata:
                packet.process = record["process"]
                packet.fields["frame.original_number"] = record["original_number"]
            elif self.process_tracker:
                packet.process = self.process_tracker.associate(packet)
            owners = packet.process.get("owners", [])
            packet.fields["pid"] = [owner["pid"] for owner in owners]
            packet.fields["process.name"] = [owner["name"] for owner in owners]
            packet.fields["process.status"] = packet.process["status"]
            if self.analyzer:
                self.analyzer.add(packet)
            while not self.error:
                try:
                    self.disk_queue.put(packet, timeout=0.05)
                    break
                except queue.Full:
                    continue
            with self.lock:
                self.stats.parsed += 1
            try:
                self.gui_queue.put_nowait(packet)
            except queue.Full:
                with self.lock:
                    self.stats.gui_queue_drops += 1

    def _write(self):
        self.ready.wait()
        if self.linktype is None:
            return
        writer = SessionWriter(self.directory, self.linktype, self.metadata["session_id"] if self.metadata else None)
        try:
            while not self.parse_done.is_set() or not self.disk_queue.empty():
                if self.error:
                    break
                try:
                    packet = self.disk_queue.get(timeout=0.05)
                except queue.Empty:
                    continue
                writer.append(packet)
                with self.lock:
                    self.stats.saved += 1
        finally:
            writer.close()

    def stop(self):
        self.stop_event.set()

    def wait(self, timeout=10):
        end = time.monotonic() + timeout
        for thread in self.threads:
            thread.join(max(0, end - time.monotonic()))
        if any(thread.is_alive() for thread in self.threads):
            raise TimeoutError("采集线程尚未退出")

    def snapshot(self):
        with self.lock:
            result = asdict(self.stats)
        elapsed = max(0.001, (self.ended_at or time.monotonic()) - self.started_at)
        result.update(elapsed=elapsed, bytes_per_second=result["bytes"] / elapsed,
                      packets_per_second=result["captured"] / elapsed, error=self.error)
        return result
