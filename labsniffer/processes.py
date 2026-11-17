import ctypes as C
import ipaddress
import os
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import psutil


DWORD = C.c_uint32


class TcpRow4(C.Structure):
    _fields_ = [(name, DWORD) for name in ("state", "local_addr", "local_port", "remote_addr", "remote_port", "pid")]


class TcpRow6(C.Structure):
    _fields_ = [("local_addr", C.c_ubyte * 16), ("local_scope", DWORD), ("local_port", DWORD),
                ("remote_addr", C.c_ubyte * 16), ("remote_scope", DWORD), ("remote_port", DWORD),
                ("state", DWORD), ("pid", DWORD)]


class TcpTable4(C.Structure):
    _fields_ = [("count", DWORD), ("rows", TcpRow4 * 1)]


class TcpTable6(C.Structure):
    _fields_ = [("count", DWORD), ("rows", TcpRow6 * 1)]


@dataclass(frozen=True)
class Connection:
    family: int
    local: tuple
    remote: tuple
    state: int
    pid: int
    name: str | None
    created: float | None
    identity_status: str
    local_scope: int = 0
    remote_scope: int = 0


class TcpTable:
    def __init__(self):
        if C.sizeof(TcpRow4) != 24 or C.sizeof(TcpRow6) != 56:
            raise RuntimeError("Windows TCP 表 ABI 大小不匹配")
        if TcpTable4.rows.offset != 4 or TcpTable6.rows.offset != 4 or TcpRow6.pid.offset != 52:
            raise RuntimeError("Windows TCP 表 ABI 字段偏移不匹配")
        self.lib = C.WinDLL(str(Path(os.environ["SystemRoot"]) / "System32" / "iphlpapi.dll"))
        self.function = self.lib.GetExtendedTcpTable
        self.function.argtypes = [C.c_void_p, C.POINTER(DWORD), C.c_int, DWORD, C.c_int, DWORD]
        self.function.restype = DWORD

    def rows(self, family):
        row_class = TcpRow4 if family == socket.AF_INET else TcpRow6
        table_class = TcpTable4 if family == socket.AF_INET else TcpTable6
        size = DWORD(0)
        result = self.function(None, C.byref(size), 0, family, 5, 0)
        if result not in (0, 122):
            raise OSError(result, "GetExtendedTcpTable 长度查询失败")
        for _ in range(4):
            if size.value > 16 * 1024 * 1024:
                raise RuntimeError("Windows TCP 表超过 16 MiB 支持上限")
            memory = C.create_string_buffer(max(size.value, 4))
            result = self.function(memory, C.byref(size), 0, family, 5, 0)
            if result == 122:
                continue
            if result != 0:
                raise OSError(result, "GetExtendedTcpTable 读取失败")
            count = DWORD.from_buffer(memory).value
            offset = table_class.rows.offset
            if offset + count * C.sizeof(row_class) > len(memory):
                raise RuntimeError("Windows TCP 表记录数超过缓冲区")
            return [row_class.from_buffer_copy(memory, offset + index * C.sizeof(row_class)) for index in range(count)]
        raise RuntimeError("Windows TCP 表持续变化，无法取得完整快照")

    def snapshot(self):
        started = time.time_ns()
        connections, identities = [], {}
        for family in (socket.AF_INET, socket.AF_INET6):
            for row in self.rows(family):
                if row.pid not in identities:
                    try:
                        process = psutil.Process(row.pid)
                        created = process.create_time()
                        name = process.name()
                        if not process.is_running():
                            identities[row.pid] = (None, None, "process_exited")
                        else:
                            identities[row.pid] = (name, created, "known")
                    except psutil.NoSuchProcess:
                        identities[row.pid] = (None, None, "process_exited")
                    except psutil.AccessDenied:
                        identities[row.pid] = (None, None, "permission_denied")
                if family == socket.AF_INET:
                    local = str(ipaddress.ip_address(row.local_addr.to_bytes(4, "little")))
                    remote = str(ipaddress.ip_address(row.remote_addr.to_bytes(4, "little")))
                    local_scope, remote_scope = 0, 0
                else:
                    local, remote = str(ipaddress.ip_address(bytes(row.local_addr))), str(ipaddress.ip_address(bytes(row.remote_addr)))
                    local_scope, remote_scope = socket.ntohl(row.local_scope), socket.ntohl(row.remote_scope)
                name, created, status = identities[row.pid]
                connections.append(Connection(family, (local, socket.ntohs(row.local_port & 0xFFFF)),
                                              (remote, socket.ntohs(row.remote_port & 0xFFFF)), row.state, row.pid,
                                              name, created, status, local_scope, remote_scope))
        return {"started_ns": started, "finished_ns": time.time_ns(), "connections": connections}


class ProcessTracker:
    def __init__(self, interval=0.2, window=0.5):
        self.api = TcpTable()
        self.interval = interval
        self.window_ns = int(window * 1_000_000_000)
        self.snapshots = deque(maxlen=8)
        self.lock = threading.Lock()
        self.event = threading.Event()
        self.error = ""
        self.thread = None

    def sample(self):
        snapshot = self.api.snapshot()
        with self.lock:
            self.snapshots.append(snapshot)
        return snapshot

    def start(self):
        if self.thread:
            raise RuntimeError("进程采样器已经启动")
        try:
            self.sample()
        except OSError as error:
            self.error = str(error)
            return
        self.thread = threading.Thread(target=self._run, name="lab-processes", daemon=False)
        self.thread.start()

    def _run(self):
        while not self.event.wait(self.interval):
            try:
                self.sample()
            except (OSError, RuntimeError) as error:
                self.error = str(error)
                return

    def stop(self):
        self.event.set()
        if self.thread:
            self.thread.join(3)
            if self.thread.is_alive():
                raise TimeoutError("进程采样线程尚未结束")

    def associate(self, packet):
        unknown = {"status": "unknown", "owners": [], "associated_ns": str(time.time_ns())}
        if "tcp" not in packet.fields:
            return {**unknown, "status": "not_tcp"}
        if self.error:
            return {**unknown, "status": "sampling_error", "reason": self.error}
        source, destination = (packet.src, packet.sport), (packet.dst, packet.dport)
        family = socket.AF_INET6 if "ipv6" in packet.fields else socket.AF_INET
        with self.lock:
            recent = [snapshot for snapshot in self.snapshots
                      if abs(packet.raw.timestamp_ns - snapshot["finished_ns"]) <= self.window_ns]
        if not recent:
            return {**unknown, "reason": "没有时间邻近的连接表快照"}
        candidates = {}
        latest_matches = set()
        for snapshot in recent:
            for row in snapshot["connections"]:
                if row.family != family or row.state in (1, 2, 12) or row.pid == 0:
                    continue
                if (row.local, row.remote) not in ((source, destination), (destination, source)):
                    continue
                if row.local_scope or row.remote_scope:
                    return {**unknown, "status": "uncertain_scope", "reason": "抓包中没有充分的 IPv6 scope 标识"}
                if row.identity_status != "known" or row.created is None:
                    return {**unknown, "status": row.identity_status}
                if int(row.created * 1_000_000_000) > packet.raw.timestamp_ns:
                    continue
                key = (row.local, row.remote)
                if snapshot is recent[-1]:
                    latest_matches.add(key)
                identity = (row.pid, row.created)
                candidates.setdefault(key, {})[identity] = {
                    "pid": row.pid, "name": row.name, "created": row.created,
                    "local": f"{row.local[0]}:{row.local[1]}", "remote": f"{row.remote[0]}:{row.remote[1]}",
                    "sample_started_ns": str(snapshot["started_ns"]), "sample_ns": str(snapshot["finished_ns"])}
        if any(len(values) != 1 for values in candidates.values()):
            return {**unknown, "status": "uncertain_reuse", "reason": "邻近快照存在 PID 或端口复用"}
        if set(candidates) - latest_matches:
            return {**unknown, "status": "uncertain_stale", "reason": "最新快照中连接已经消失"}
        owners = [next(iter(values.values())) for values in candidates.values()]
        if not owners:
            return {**unknown, "reason": "连接在采样时不可见，可能为短连接、退出或非本机连接"}
        return {**unknown, "status": "observed", "owners": owners, "window_ms": self.window_ns // 1_000_000}
