from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from labsniffer.models import RawPacket
from labsniffer.protocols import parse_packet
from labsniffer.streams import StreamManager


def packet(number, seq, payload=b"", flags="PA", reverse=False, timestamp=None):
    src, dst, sport, dport = ("192.0.2.1", "192.0.2.2", 40000, 18080)
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    data = bytes(Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, seq=seq, flags=flags)/Raw(payload))
    return parse_packet(RawPacket(number, timestamp or number * 1_000_000, data, len(data), 1))


def test_out_of_order_retransmission_http_and_gaps():
    manager = StreamManager()
    manager.add(packet(1, 100, flags="S"))
    header = b"GET /split HTTP/1.1\r\nHost: lab.test\r\n\r\n"
    manager.add(packet(2, 121, header[20:]))
    stream = manager.get(0)
    assert stream["directions"][0]["gaps"]
    assert not stream["http"][0]
    result = packet(3, 101, header[:20])
    manager.add(result)
    assert result.protocol == "HTTP"
    assert result.fields["http.path"] == "/split"
    manager.add(packet(4, 101, header[:20]))
    manager.add(packet(5, 101, b"BAD"))
    stream = manager.get(0)
    assert stream["directions"][0]["data"] == header
    assert stream["directions"][0]["duplicate_bytes"] >= 20
    assert stream["directions"][0]["conflict_bytes"] == 3


def test_bidirectional_lifecycle_and_port_reuse():
    manager = StreamManager()
    a, b = packet(1, 10, flags="S"), packet(2, 20, flags="SA", reverse=True)
    manager.add(a)
    manager.add(b)
    assert a.stream_id == b.stream_id
    manager.add(packet(3, 11, flags="A"))
    manager.add(packet(4, 11, flags="FA"))
    manager.add(packet(5, 21, flags="FA", reverse=True))
    assert manager.get(0)["state"] == "CLOSED"
    new = packet(6, 500, flags="S")
    manager.add(new)
    assert new.stream_id == 1
    assert len(manager.snapshot()) == 2


def test_sequence_wrap_and_midstream_uncertainty():
    manager = StreamManager()
    manager.add(packet(1, 0xFFFFFFFD, flags="S"))
    manager.add(packet(2, 0xFFFFFFFE, b"ab"))
    manager.add(packet(3, 0, b"cd"))
    assert manager.get(0)["directions"][0]["data"] == b"abcd"
    manager = StreamManager()
    manager.add(packet(1, 100, b"later"))
    assert manager.get(0)["directions"][0]["missing_prefix"]
