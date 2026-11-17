import json
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from scapy.layers.dns import DNS, DNSQR, DNSRR

from labsniffer.capture import CaptureEngine
from labsniffer.filters import compile_filter
from labsniffer.gui import MainWindow
from labsniffer.npcap import CaptureConfig, Npcap
from labsniffer.processes import ProcessTracker
from labsniffer.protocols import parse_packet
from labsniffer.storage import PcapFile, export_session, load_metadata
from labsniffer.streams import StreamManager
from test_wireshark import table


def loopback():
    return next(device.name for device in Npcap().devices() if "Loopback" in device.name)


@pytest.mark.live
def test_dns_ipv6_udp_and_icmp(evidence_dir):
    engine = CaptureEngine(evidence_dir, CaptureConfig(loopback(), "udp port 53 or icmp or icmp6"), parser=parse_packet)
    engine.start()
    try:
        assert engine.ready.wait(5) and not engine.error, engine.error
        for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            with socket.socket(family, socket.SOCK_DGRAM) as server, socket.socket(family, socket.SOCK_DGRAM) as client:
                server.bind((host, 53))
                server.settimeout(2)
                client.settimeout(2)
                query = DNS(id=12345, qd=DNSQR(qname="lab.example", qtype="A"))
                client.sendto(bytes(query), (host, 53))
                data, remote = server.recvfrom(4096)
                received = DNS(data)
                assert received.id == 12345
                answer = DNS(id=received.id, qr=1, aa=1, qd=received.qd,
                             an=DNSRR(rrname="lab.example", type="A", ttl=30, rdata="192.0.2.20"))
                server.sendto(bytes(answer), remote)
                assert DNS(client.recvfrom(4096)[0]).an[0].rdata == "192.0.2.20"
        ping_results = []
        for host in ("127.0.0.1", "::1"):
            result = subprocess.run(["ping", "-n", "1", "-w", "1000", host], capture_output=True, timeout=5)
            assert result.returncode == 0
            ping_results.append({"host": host, "exit_code": result.returncode})
        time.sleep(0.15)
    finally:
        engine.stop()
        engine.wait(5)
    assert not engine.error, engine.error
    path = engine.directory / "capture.pcap"
    packets = [parse_packet(raw) for raw in PcapFile.read(path)]
    assert sum("dns" in packet.fields for packet in packets) == 4
    assert any("ipv6" in packet.fields and "udp" in packet.fields for packet in packets)
    assert {"ICMP", "ICMPv6"} <= {packet.protocol for packet in packets}
    (evidence_dir / "dns_icmp.json").write_text(json.dumps({"pcap": str(path), "ping": ping_results,
                                                         "packets": len(packets)}, indent=2), encoding="utf-8")


@pytest.mark.live
def test_child_process_exit(evidence_dir):
    tracker = ProcessTracker()
    tracker.start()
    assert not tracker.error, tracker.error
    streams = StreamManager()
    engine = CaptureEngine(evidence_dir, CaptureConfig(loopback(), "tcp port 18082"), parser=parse_packet,
                           analyzer=streams, process_tracker=tracker)
    engine.start()
    try:
        assert engine.ready.wait(5) and not engine.error
        child = subprocess.Popen([sys.executable, "-m", "labsniffer.traffic", "--port", "18082", "--flows", "3"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = child.communicate(timeout=15)
        assert child.returncode == 0, stderr.decode(errors="replace")
        actual_pid = json.loads(stdout)["pid"]
        time.sleep(0.7)
        snapshot = tracker.sample()
        assert not any(row.pid == actual_pid and row.state == 5 for row in snapshot["connections"])
    finally:
        engine.stop()
        engine.wait(5)
        tracker.stop()
    assert not engine.error, engine.error
    assert len(streams.snapshot()) == 3
    assert all(any(owner["pid"] == actual_pid for owner in flow["owners"]) for flow in streams.snapshot())
    path, _ = export_session(engine.directory, evidence_dir / f"child_{uuid.uuid4().hex}.pcap")
    assert any(item["process"]["owners"] for item in load_metadata(path)["packets"])
    (evidence_dir / "child_exit.json").write_text(json.dumps({"pid": actual_pid, "launcher_pid": child.pid, "exit_code": child.returncode,
        "stdout": stdout.decode(errors="replace"), "active_connections_after_exit": 0, "pcap": str(path),
        "flows": streams.snapshot()}, ensure_ascii=False, indent=2), encoding="utf-8")


@pytest.mark.live
@pytest.mark.gui
def test_sustained_gui_and_filter_semantics(evidence_dir):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    ticks, errors = [], []
    heartbeat = QTimer()
    heartbeat.setInterval(20)
    heartbeat.timeout.connect(lambda: ticks.append(time.monotonic()))
    heartbeat.start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as excluded:
        server.bind(("127.0.0.1", 0))
        excluded.bind(("127.0.0.1", 0))
        server.settimeout(2)
        port = server.getsockname()[1]
        excluded_port = excluded.getsockname()[1]
        window.begin(config=CaptureConfig(loopback(), f"udp port {port}"))
        assert window.engine.ready.wait(5) and not window.engine.error

        def generate():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    for index in range(1200):
                        payload = f"UCAS_GUI_REAL_{index}".encode()
                        client.sendto(payload, ("127.0.0.1", port))
                        assert server.recvfrom(4096)[0] == payload
                        if index % 20 == 0:
                            client.sendto(b"excluded by BPF", ("127.0.0.1", excluded_port))
                        time.sleep(0.002)
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=generate)
        worker.start()
        deadline = time.monotonic() + 15
        while worker.is_alive() and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.002)
        worker.join(1)
        assert not worker.is_alive() and not errors, errors
        window.stop_capture()
        while not window.engine.finished.is_set() and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.002)
        window.engine.wait(2)
        window.refresh_packets()
        assert not window.engine.error, window.engine.error
        window.set_filter("tcp")
        assert window.model.rowCount() == 0
        assert window.engine.stats.saved == 1200
        path = evidence_dir / f"gui_export_{uuid.uuid4().hex}.pcap"
        window.begin_export(path)
        while window.export_thread.is_alive():
            app.processEvents()
            time.sleep(0.002)
        window.refresh_packets()
        packets = [parse_packet(raw) for raw in PcapFile.read(path)]
        assert len(packets) == 1200
        assert all(packet.dport == port for packet in packets)
        assert all(not compile_filter("tcp")(packet) for packet in packets)
        assert len(window.history) <= 5000 and window.history_bytes <= 32 * 1024 * 1024
        heartbeat.stop()
        assert len(ticks) >= 40
        max_delay = max(right - left for left, right in zip(ticks, ticks[1:]))
        assert max_delay < 1.0
        record = {"pcap": str(path), "generated": 1200, "excluded_by_bpf": 60, "heartbeat_ticks": len(ticks),
                  "max_heartbeat_gap_seconds": max_delay, "stats": window.engine.snapshot()}
        (evidence_dir / "gui_sustained.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    window.close()
    app.processEvents()


@pytest.mark.wireshark
def test_same_capture_field_comparison(evidence_dir):
    reports = []
    for record_name in ("tcp_pid_18080", "tcp_pid_18081", "tcp_pid_80", "dns_icmp"):
        record_file = evidence_dir / f"{record_name}.json"
        if not record_file.exists():
            pytest.skip(f"缺少真实流量前置证据：{record_name}")
        record = json.loads(record_file.read_text(encoding="utf-8"))
        path = Path(record["pcap"])
        args = ["-r", path]
        if record.get("port") in (18080, 18081):
            args += ["-d", f"tcp.port=={record['port']},http"]
        fields = ["frame.number", "frame.cap_len", "frame.len", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
                  "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "tcp.seq_raw", "dns.id", "http.request.method"]
        rows, result = table(args, fields, scripts=())
        packets = [parse_packet(raw) for raw in PcapFile.read(path)]
        assert len(rows) == len(packets)
        for packet, row in zip(packets, rows):
            assert [str(packet.raw.number), str(packet.raw.caplen), str(packet.raw.wirelen)] == row[:3]
            assert packet.src == (row[3] or row[4]) and packet.dst == (row[5] or row[6])
            assert str(packet.sport or "") == (row[7] or row[8])
            assert str(packet.dport or "") == (row[9] or row[10])
            if "tcp" in packet.fields:
                assert str(packet.fields["tcp.seq"]) == row[11]
            if "dns" in packet.fields:
                assert packet.fields["dns.id"] == int(row[12], 16)
        if record.get("port"):
            assert sum(row[13] == "GET" for row in rows) == 3
        (evidence_dir / f"comparison_{record_name}.csv").write_text(result.stdout, encoding="utf-8")
        reports.append({"source": record_name, "pcap": str(path), "packets_compared": len(rows),
                        "fields": fields, "status": "PASS", "decode_as": args[args.index("-d") + 1] if "-d" in args else None})
    (evidence_dir / "field_comparison.json").write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
