from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class RawPacket:
    number: int
    timestamp_ns: int
    data: bytes
    wirelen: int
    linktype: int

    @property
    def caplen(self):
        return len(self.data)


@dataclass(slots=True)
class Packet:
    raw: RawPacket
    src: str = ""
    dst: str = ""
    sport: int | None = None
    dport: int | None = None
    protocol: str = "UNKNOWN"
    summary: str = ""
    layers: dict[str, dict[str, Any]] = field(default_factory=dict)
    fields: dict[str, Any] = field(default_factory=dict)
    payload: bytes = b""
    errors: list[str] = field(default_factory=list)
    stream_id: int | None = None
    process: dict = field(default_factory=lambda: {"status": "unknown", "owners": []})

    def layer(self, name, values):
        self.layers[name] = values
        self.fields[name.lower()] = True
        for key, value in values.items():
            self.fields[f"{name.lower()}.{key}"] = value
        self.protocol = name


@dataclass(slots=True)
class CaptureStats:
    captured: int = 0
    bytes: int = 0
    wire_bytes: int = 0
    parsed: int = 0
    saved: int = 0
    capture_queue_drops: int = 0
    gui_queue_drops: int = 0
    driver_received: int | None = None
    driver_drops: int | None = None
    interface_drops: int | None = None
    stats_error: str = ""
