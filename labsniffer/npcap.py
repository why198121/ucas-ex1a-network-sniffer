import ctypes as C
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

import pefile

from .models import RawPacket


class CaptureError(RuntimeError):
    pass


# Windows LLP64 中 long 保持 32 位；timeval 必须采用 Winsock 的布局。
class Timeval(C.Structure):
    _fields_ = [("sec", C.c_int32), ("usec", C.c_int32)]


class Header(C.Structure):
    _fields_ = [("ts", Timeval), ("caplen", C.c_uint32), ("wirelen", C.c_uint32)]


class BpfProgram(C.Structure):
    _fields_ = [("length", C.c_uint32), ("instructions", C.c_void_p)]


class PcapStats(C.Structure):
    _fields_ = [(name, C.c_uint32) for name in ("recv", "drop", "ifdrop", "capt", "sent", "netdrop")]


class Sockaddr(C.Structure):
    _fields_ = [("family", C.c_uint16), ("data", C.c_ubyte * 14)]


class Sockaddr4(C.Structure):
    _fields_ = [("family", C.c_uint16), ("port", C.c_uint16), ("address", C.c_ubyte * 4), ("zero", C.c_ubyte * 8)]


class Sockaddr6(C.Structure):
    _fields_ = [("family", C.c_uint16), ("port", C.c_uint16), ("flow", C.c_uint32),
                ("address", C.c_ubyte * 16), ("scope", C.c_uint32)]


class Address(C.Structure):
    pass


Address._fields_ = [("next", C.POINTER(Address))] + [(name, C.POINTER(Sockaddr)) for name in ("addr", "netmask", "broadcast", "destination")]


class Interface(C.Structure):
    pass


Interface._fields_ = [("next", C.POINTER(Interface)), ("name", C.c_char_p), ("description", C.c_char_p),
                     ("addresses", C.POINTER(Address)), ("flags", C.c_uint32)]


@dataclass(frozen=True)
class Device:
    name: str
    description: str
    addresses: tuple[str, ...]
    flags: int


@dataclass(frozen=True)
class CaptureConfig:
    device: str
    bpf: str = ""
    snaplen: int = 65535
    promiscuous: bool = True
    timeout_ms: int = 100
    buffer_mb: int = 8

    def __post_init__(self):
        if not self.device or not 64 <= self.snaplen <= 262144:
            raise ValueError("请选择网卡；捕获长度必须为 64–262144 字节")
        if not 1 <= self.timeout_ms <= 10000 or not 1 <= self.buffer_mb <= 256:
            raise ValueError("超时必须为 1–10000 毫秒，驱动缓冲区必须为 1–256 MiB")


class Npcap:
    def __init__(self):
        if sys.platform != "win32" or C.sizeof(C.c_void_p) != 8:
            raise CaptureError("实时抓包需要 Windows x64 和 64 位 Python")
        directory = Path(os.environ["SystemRoot"]) / "System32" / "Npcap"
        path = directory / "wpcap.dll"
        if not path.is_file():
            raise CaptureError(f"未找到 Npcap：{path}。请安装 Npcap x64 驱动。")
        for filename in ("wpcap.dll", "Packet.dll"):
            with pefile.PE(str(directory / filename), fast_load=True) as pe:
                if pe.FILE_HEADER.Machine != 0x8664:
                    raise CaptureError(f"Npcap DLL 位数不兼容：{filename}")
        self.dll_directory = os.add_dll_directory(str(directory))
        self.lib = C.CDLL(str(path))
        self.path = str(path)
        self._bind()
        self._check_layout()

    @staticmethod
    def _check_layout():
        expected = {Timeval: 8, Header: 16, BpfProgram: 16, PcapStats: 24,
                    Sockaddr4: 16, Sockaddr6: 28, Address: 40, Interface: 40}
        for structure, size in expected.items():
            if C.sizeof(structure) != size:
                raise CaptureError(f"ABI 布局不匹配：{structure.__name__}")
        if Header.caplen.offset != 8 or BpfProgram.instructions.offset != 8 or Interface.flags.offset != 32:
            raise CaptureError("Npcap ABI 字段偏移不匹配")

    def _bind(self):
        ptr, integer, char = C.c_void_p, C.c_int, C.c_char_p
        signatures = {
            "pcap_lib_version": (char, []),
            "pcap_findalldevs": (integer, [C.POINTER(C.POINTER(Interface)), char]),
            "pcap_freealldevs": (None, [C.POINTER(Interface)]),
            "pcap_create": (ptr, [char, char]),
            "pcap_activate": (integer, [ptr]),
            "pcap_close": (None, [ptr]),
            "pcap_datalink": (integer, [ptr]),
            "pcap_geterr": (char, [ptr]),
            "pcap_statustostr": (char, [integer]),
            "pcap_next_ex": (integer, [ptr, C.POINTER(C.POINTER(Header)), C.POINTER(C.POINTER(C.c_ubyte))]),
            "pcap_compile": (integer, [ptr, C.POINTER(BpfProgram), char, integer, C.c_uint32]),
            "pcap_setfilter": (integer, [ptr, C.POINTER(BpfProgram)]),
            "pcap_freecode": (None, [C.POINTER(BpfProgram)]),
            "pcap_setnonblock": (integer, [ptr, integer, char]),
            "pcap_stats": (integer, [ptr, C.POINTER(PcapStats)]),
        }
        for name in ("pcap_set_snaplen", "pcap_set_promisc", "pcap_set_timeout", "pcap_set_buffer_size", "pcap_set_immediate_mode"):
            signatures[name] = (integer, [ptr, integer])
        for name, (result, arguments) in signatures.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = result, arguments

    @property
    def version(self):
        return self.lib.pcap_lib_version().decode("utf-8", errors="replace")

    def devices(self):
        head = C.POINTER(Interface)()
        error = C.create_string_buffer(256)
        if self.lib.pcap_findalldevs(C.byref(head), error) != 0:
            raise CaptureError(f"网卡枚举失败：{error.value.decode(errors='replace')}")
        devices = []
        try:
            current = head
            while current:
                item = current.contents
                addresses = []
                address = item.addresses
                while address:
                    pointer = address.contents.addr
                    if pointer and pointer.contents.family == socket.AF_INET:
                        value = C.cast(pointer, C.POINTER(Sockaddr4)).contents
                        addresses.append(socket.inet_ntop(socket.AF_INET, bytes(value.address)))
                    elif pointer and pointer.contents.family == socket.AF_INET6:
                        value = C.cast(pointer, C.POINTER(Sockaddr6)).contents
                        text = socket.inet_ntop(socket.AF_INET6, bytes(value.address))
                        addresses.append(f"{text}%{value.scope}" if value.scope else text)
                    address = address.contents.next
                devices.append(Device(item.name.decode(), (item.description or b"").decode(errors="replace"), tuple(addresses), item.flags))
                current = item.next
        finally:
            self.lib.pcap_freealldevs(head)
        return devices

    def open(self, config):
        return CaptureHandle(self, config)


class CaptureHandle:
    def __init__(self, api, config):
        self.api = api
        self.lib = api.lib
        self.handle = None
        self.warnings = []
        error = C.create_string_buffer(256)
        self.handle = self.lib.pcap_create(config.device.encode(), error)
        if not self.handle:
            raise CaptureError(f"无法打开网卡：{error.value.decode(errors='replace')}；检查设备和抓包权限")
        try:
            for name, value in (("pcap_set_snaplen", config.snaplen), ("pcap_set_promisc", int(config.promiscuous)),
                                ("pcap_set_timeout", config.timeout_ms), ("pcap_set_buffer_size", config.buffer_mb * 1024 * 1024),
                                ("pcap_set_immediate_mode", 1)):
                self._check(getattr(self.lib, name)(self.handle, value), name)
            status = self.lib.pcap_activate(self.handle)
            if status < 0:
                raise CaptureError(f"网卡激活失败：{self.error()}；检查 Npcap 服务、设备状态和管理员权限")
            if status > 0:
                self.warnings.append(self.lib.pcap_statustostr(status).decode(errors="replace"))
            self.linktype = self.lib.pcap_datalink(self.handle)
            if self.linktype < 0:
                raise CaptureError(self.error())
            if config.bpf:
                program = BpfProgram()
                self._check(self.lib.pcap_compile(self.handle, C.byref(program), config.bpf.encode(), 1, 0xFFFFFFFF), "抓包过滤式错误")
                try:
                    self._check(self.lib.pcap_setfilter(self.handle, C.byref(program)), "设置抓包过滤失败")
                finally:
                    self.lib.pcap_freecode(C.byref(program))
            self._check(self.lib.pcap_setnonblock(self.handle, 1, error), "设置非阻塞读取失败")
        except BaseException:
            self.close()
            raise

    def _check(self, result, operation):
        if result != 0:
            raise CaptureError(f"{operation}：{self.error()}")

    def error(self):
        return self.lib.pcap_geterr(self.handle).decode(errors="replace")

    def next_packet(self, number):
        header = C.POINTER(Header)()
        data = C.POINTER(C.c_ubyte)()
        status = self.lib.pcap_next_ex(self.handle, C.byref(header), C.byref(data))
        if status == 0:
            return None
        if status != 1:
            raise CaptureError(f"读取网卡失败（{status}）：{self.error()}")
        value = header.contents
        if value.caplen > 262144 or value.caplen > value.wirelen or not 0 <= value.ts.usec < 1_000_000:
            raise CaptureError("Npcap 返回了不满足 ABI 约束的包头")
        # 指针只在下一次读取前有效，必须立即复制，禁止跨线程传递驱动指针。
        return RawPacket(number, value.ts.sec * 1_000_000_000 + value.ts.usec * 1000,
                         C.string_at(data, value.caplen), value.wirelen, self.linktype)

    def stats(self):
        value = PcapStats()
        if self.lib.pcap_stats(self.handle, C.byref(value)) != 0:
            return {"driver_received": None, "driver_drops": None, "interface_drops": None, "stats_error": self.error()}
        return {"driver_received": value.recv, "driver_drops": value.drop,
                "interface_drops": value.ifdrop if value.ifdrop else None, "stats_error": ""}

    def close(self):
        if self.handle:
            self.lib.pcap_close(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
