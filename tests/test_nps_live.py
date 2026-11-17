import json
import socket
import time
import uuid

import pytest
from PySide6.QtWidgets import QApplication

from labsniffer.capture import CaptureEngine
from labsniffer.gui import MainWindow
from labsniffer.npcap import CaptureConfig, CaptureError, Npcap
from labsniffer.storage import PcapFile, export_session, load_metadata


@pytest.mark.live
def test_real_udp_capture_restart_and_idle_stop(evidence_dir):
    api = Npcap()
    devices = api.devices()
    loopback = next(device for device in devices if "Loopback" in device.name)
    results = []
    for cycle in range(2):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(("127.0.0.1", 0))
            server.settimeout(2)
            port = server.getsockname()[1]
            engine = CaptureEngine(evidence_dir, CaptureConfig(loopback.name, f"udp port {port}"))
            engine.start()
            assert engine.ready.wait(5)
            assert not engine.error, engine.error
            marker = ("UCAS_REAL_UDP_" + str(uuid.uuid4())).encode()
            before = time.time_ns()
            client.sendto(marker, ("127.0.0.1", port))
            data, address = server.recvfrom(4096)
            assert data == marker
            server.sendto(b"ACK:" + data, address)
            assert client.recvfrom(4096)[0] == b"ACK:" + marker
            deadline = time.monotonic() + 3
            while engine.stats.saved < 2 and time.monotonic() < deadline and not engine.error:
                time.sleep(0.02)
            stop_at = time.monotonic()
            engine.stop()
            engine.wait(3)
            latency = time.monotonic() - stop_at
            assert latency < 2
            assert not engine.error, engine.error
            packets = list(PcapFile.read(engine.directory / "capture.pcap"))
            assert any(marker in packet.data for packet in packets)
            assert all(before - 1_000_000_000 <= packet.timestamp_ns <= time.time_ns() for packet in packets)
            exported, _ = export_session(engine.directory, evidence_dir / f"real_udp_{uuid.uuid4().hex}.pcap")
            assert load_metadata(exported)["packet_count"] == len(packets)
            results.append({"cycle": cycle, "stop_seconds": latency, "pcap": str(exported), "stats": engine.snapshot()})
    (evidence_dir / "nps_live.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")


@pytest.mark.live
def test_invalid_bpf_fails():
    api = Npcap()
    loopback = next(device for device in api.devices() if "Loopback" in device.name)
    with pytest.raises(CaptureError, match="过滤"):
        api.open(CaptureConfig(loopback.name, "tcp and and malformed"))


@pytest.mark.gui
def test_gui_real_event_loop_idle_stop():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    window.bpf.setText("udp port 59998")
    window.start_capture()
    deadline = time.monotonic() + 1
    ticks = 0
    while time.monotonic() < deadline:
        app.processEvents()
        ticks += 1
        time.sleep(0.01)
    assert ticks > 20
    window.stop_capture()
    deadline = time.monotonic() + 3
    while not window.engine.finished.is_set() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    window.engine.wait(1)
    assert not window.engine.error
    window.close()
    app.processEvents()
