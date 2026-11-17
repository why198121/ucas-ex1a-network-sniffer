import struct

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment, ICMPv6EchoRequest
from scapy.layers.l2 import ARP, Dot1Q, Ether, Loopback
from scapy.packet import Raw

from labsniffer.models import RawPacket
from labsniffer.protocols import parse_packet


def parse(data, linktype=1, wirelen=None):
    data = bytes(data)
    return parse_packet(RawPacket(1, 1_790_000_000_000_000_000, data, wirelen or len(data), linktype))


def test_vlan_options_and_endpoints():
    packet = parse(Ether()/Dot1Q(vlan=42)/IP(src="192.0.2.1", dst="192.0.2.2", options=b"\x01\x01\x01\x01")/
                   TCP(sport=31000, dport=8080, flags="S", options=[("MSS", 1460)]))
    assert packet.protocol == "TCP"
    assert packet.fields["vlan.id"] == [42]
    assert packet.fields["ipv4.header_length"] == 24
    assert packet.fields["tcp.header_length"] == 24
    assert packet.sport == 31000
    assert not packet.errors


def test_ipv6_extensions_and_fragment_safety():
    packet = parse(Ether()/IPv6(src="::1", dst="::1")/IPv6ExtHdrDestOpt()/UDP(sport=1000, dport=2000)/Raw(b"ok"))
    assert packet.protocol == "UDP"
    fragment = parse(Ether()/IPv6()/IPv6ExtHdrFragment(offset=1, m=1)/Raw(b"\x00" * 24))
    assert fragment.sport is None
    assert fragment.fields["ip.fragmented"]
    first_fragment = parse(Ether()/IP(flags="MF")/UDP()/Raw(b"x"))
    assert first_fragment.sport is None


def test_dns_compression_and_bounds():
    dns = DNS(id=123, qr=1, qd=DNSQR(qname="example.test"), an=DNSRR(rrname="example.test", rdata="192.0.2.8"))
    packet = parse(Ether()/IP()/UDP(sport=53, dport=40000)/dns)
    assert packet.protocol == "DNS"
    assert packet.fields["dns.id"] == 123
    assert "192.0.2.8" in str(packet.layers["DNS"])
    cyclic = struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
    packet = parse(Ether()/IP()/UDP(sport=53, dport=40000)/Raw(cyclic))
    assert packet.errors
    assert packet.protocol == "UDP"


def test_protocols_loopback_and_truncated_packets():
    for transport, expected in [(ICMP(), "ICMP"), (UDP(), "UDP"), (TCP(), "TCP")]:
        assert parse(struct.pack("<I", 2) + bytes(IP()/transport), 0).protocol == expected
    assert parse(struct.pack("<I", 24) + bytes(IPv6()/ICMPv6EchoRequest()), 0).protocol == "ICMPv6"
    assert parse(Ether()/ARP()).protocol == "ARP"
    full = bytes(Ether()/IP()/TCP()/Raw(b"data"))
    for end in range(len(full)):
        packet = parse(full[:end], wirelen=len(full))
        assert packet.fields["frame.truncated"]
        assert packet.errors


def test_port_80_alone_is_not_http():
    packet = parse(Ether()/IP()/TCP(dport=80)/Raw(b"random application bytes"))
    assert packet.protocol == "TCP"
