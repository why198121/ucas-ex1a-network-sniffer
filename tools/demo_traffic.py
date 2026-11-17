import json
import os
import socket
import subprocess
import sys
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from labsniffer.demo import DemoServer, exercise
from labsniffer.traffic import HttpLab


def main():
    destination = Path(sys.argv[1])
    with HttpLab('127.0.0.1', 18080) as server:
        responses = server.exercise(3)
    with DemoServer() as server:
        demo = exercise(port=server.port)
    for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
        with socket.socket(family, socket.SOCK_DGRAM) as server, socket.socket(family, socket.SOCK_DGRAM) as client:
            server.bind((host, 53))
            server.settimeout(3)
            client.settimeout(3)
            client.sendto(bytes(DNS(id=12345, qd=DNSQR(qname='lab.example'))), (host, 53))
            data, remote = server.recvfrom(4096)
            query = DNS(data)
            answer = DNS(id=query.id, qr=1, aa=1, qd=query.qd,
                         an=DNSRR(rrname='lab.example', type='A', ttl=30, rdata='192.0.2.20'))
            server.sendto(bytes(answer), remote)
            assert DNS(client.recvfrom(4096)[0]).an[0].rdata == '192.0.2.20'
    for host in ('127.0.0.1', '::1'):
        result = subprocess.run(['ping', '-n', '1', '-w', '1000', host], capture_output=True, timeout=5)
        assert result.returncode == 0
    record = {'status': 'PASS', 'pid': os.getpid(), 'http_flows': len(responses), 'labdemo': demo,
              'dns': ['127.0.0.1', '::1'], 'icmp': ['127.0.0.1', '::1']}
    destination.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
