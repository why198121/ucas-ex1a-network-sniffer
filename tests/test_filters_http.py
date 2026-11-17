import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from labsniffer.filters import FilterError, compile_filter
from labsniffer.http import inspect_http
from labsniffer.models import RawPacket
from labsniffer.protocols import parse_packet


def test_display_filter_logic_and_validation():
    data = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.1", dst="192.0.2.2")/TCP(sport=12000, dport=8080))
    packet = parse_packet(RawPacket(1, 0, data, len(data), 1))
    assert compile_filter('tcp and (port == 8080 or addr == "198.51.100.1") and not udp')(packet)
    assert not compile_filter("udp or port == 53")(packet)
    assert packet.raw.data == data
    for text in ('__import__("os")', 'unknown == 1', 'port == "80"', 'addr == 80', 'port == 99999', 'tcp and'):
        with pytest.raises(FilterError):
            compile_filter(text)


def test_http_structure_content_length_and_pipelining():
    data = b"POST /lab HTTP/1.1\r\nHost: lab.test\r\nContent-Length: 3\r\n\r\nabcGET /next HTTP/1.1\r\nHost: lab.test\r\n\r\n"
    messages = inspect_http(data)
    assert [m["path"] for m in messages] == ["/lab", "/next"]
    assert messages[0]["body_preview"] == "abc"
    assert inspect_http(b"not http\r\n\r\n") == []
    assert inspect_http(data[:40]) == []


def test_chunked_body_and_conflicting_lengths():
    message = inspect_http(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")[0]
    assert message["body_preview"] == "abc"
    assert message["complete"]
    malformed = inspect_http(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc")[0]
    assert not malformed["complete"]
    assert "冲突" in malformed["body_state"]
    head = inspect_http(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", request_methods=["HEAD"])[0]
    assert head["complete"]
