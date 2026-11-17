import json
import os
import socket
import time
import uuid

import pytest

from labsniffer.capture import CaptureEngine
from labsniffer.npcap import CaptureConfig, Npcap
from labsniffer.processes import ProcessTracker, TcpTable
from labsniffer.protocols import parse_packet
from labsniffer.storage import PcapFile, export_session, load_metadata
from labsniffer.streams import StreamManager
from labsniffer.traffic import HttpLab


@pytest.mark.live
@pytest.mark.parametrize("host,port", [("127.0.0.1", 18080), ("::1", 18081), ("127.0.0.1", 80)])
def test_real_tcp_http_and_pid(host, port, evidence_dir):
    tracker = ProcessTracker()
    tracker.start()
    assert not tracker.error, tracker.error
    streams = StreamManager()
    loopback = next(device.name for device in Npcap().devices() if "Loopback" in device.name)
    engine = CaptureEngine(evidence_dir, CaptureConfig(loopback, f"tcp port {port}"), parser=parse_packet,
                           analyzer=streams, process_tracker=tracker)
    engine.start()
    try:
        assert engine.ready.wait(5)
        assert not engine.error, engine.error
        with HttpLab(host, port) as server:
            assert len(server.exercise(3)) == 3
        time.sleep(0.2)
    finally:
        engine.stop()
        engine.wait(5)
        tracker.stop()
    assert not engine.error, engine.error
    flows = streams.snapshot()
    assert len(flows) == 3
    assert all(any(owner["pid"] == os.getpid() for owner in flow["owners"]) for flow in flows)
    assert all(streams.get(flow["id"])["http"][0] for flow in flows)
    assert all(streams.get(flow["id"])["http"][1] for flow in flows)
    path, _ = export_session(engine.directory, evidence_dir / f"real_http_{port}_{uuid.uuid4().hex}.pcap")
    metadata = load_metadata(path)
    assert any(item["process"]["status"] == "observed" for item in metadata["packets"])
    assert all(item.linktype == 0 for item in PcapFile.read(path))
    record = {"host": host, "port": port, "pid": os.getpid(), "pcap": str(path), "flows": flows, "stats": engine.snapshot()}
    (evidence_dir / f"tcp_pid_{port}.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
