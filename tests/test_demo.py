import socket

import pytest

from labsniffer.demo import DemoServer, decode, encode


@pytest.mark.live
def test_maximum_payload_produces_bounded_error_and_server_continues():
    with DemoServer(port=0) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(encode(1, 0xFFFFFFFF, b"x" * 4096), ("127.0.0.1", server.port))
        response = decode(client.recvfrom(8192)[0])
        assert response["valid"] and response["type"] == 3 and response["request_id"] == 0xFFFFFFFF
        client.sendto(encode(1, 1, b"small"), ("127.0.0.1", server.port))
        response = decode(client.recvfrom(8192)[0])
        assert response["type"] == 2 and response["payload"] == "ACK:small"
