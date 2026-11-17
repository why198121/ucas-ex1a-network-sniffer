import csv
import io
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from labsniffer.capture import CaptureEngine
from labsniffer.cli import find_wireshark
from labsniffer.demo import DemoServer, HEADER, MAGIC, decode, encode, exercise
from labsniffer.models import RawPacket
from labsniffer.npcap import CaptureConfig, Npcap
from labsniffer.protocols import parse_packet
from labsniffer.storage import PcapFile, load_metadata


ROOT = Path(__file__).resolve().parents[1]


def tshark_path():
    try:
        return find_wireshark("tshark.exe")
    except FileNotFoundError as error:
        pytest.skip(str(error))


def tshark(arguments, scripts=("labdemo.lua", "labproc.lua")):
    command = [str(tshark_path())]
    for script in scripts:
        command += ["-X", f"lua_script:{ROOT / 'wireshark' / script}"]
    command += list(map(str, arguments))
    result = subprocess.run(command, capture_output=True, encoding="utf-8", errors="replace", timeout=45)
    evidence = Path(os.environ.get("LAB_EVIDENCE_DIR", ROOT / ".work/test-evidence"))
    evidence.mkdir(parents=True, exist_ok=True)
    with (evidence / "tshark-calls.jsonl").open("a", encoding="utf-8") as log:
        log.write(json.dumps({"command": command, "exit_code": result.returncode, "stderr": result.stderr}, ensure_ascii=False) + "\n")
    assert result.returncode == 0, result.stderr
    assert "Unable to load" not in result.stderr, result.stderr
    assert "Lua Error" not in result.stderr and "Lua: " not in result.stderr, result.stderr
    return result


def table(arguments, fields, scripts=("labdemo.lua", "labproc.lua")):
    command = list(arguments) + ["-T", "fields", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=a"]
    for field in fields:
        command += ["-e", field]
    command += ["-e", "_ws.lua.error"]
    result = tshark(command, scripts)
    rows = list(csv.reader(io.StringIO(result.stdout)))
    assert all(not row[-1] for row in rows), rows
    return [row[:-1] for row in rows], result


@pytest.mark.wireshark
def test_runtime_plugins_and_interfaces(evidence_dir):
    interfaces = tshark(["-D"])
    assert "Unable to load" not in interfaces.stderr, interfaces.stderr
    assert "\\Device\\NPF_Loopback" in interfaces.stdout, interfaces.stdout
    plugins = tshark(["-G", "plugins"])
    assert "Unable to load" not in plugins.stderr, plugins.stderr
    assert "falco-events.dll" in plugins.stdout
    for name in ("labdemo.lua", "labproc.lua"):
        assert name in plugins.stdout
    protocols = tshark(["-G", "protocols"])
    registered = {row[2] for row in csv.reader(io.StringIO(protocols.stdout), delimiter="\t") if len(row) >= 3}
    assert {"cloudtrail", "gcpaudit", "k8saudit", "labdemo", "labproc"} <= registered
    (evidence_dir / "wireshark_runtime.json").write_text(json.dumps({
        "status": "PASS", "executable": str(tshark_path()), "interfaces": interfaces.stdout.splitlines(),
        "stderr": interfaces.stderr + plugins.stderr + protocols.stderr, "plugins": plugins.stdout.splitlines(),
        "verified_protocols": ["cloudtrail", "gcpaudit", "k8saudit", "labdemo", "labproc"]
    }, ensure_ascii=False, indent=2), encoding="utf-8")


@pytest.mark.wireshark
def test_demo_offline_boundaries_and_fields(evidence_dir):
    payloads = [encode(1, 10, b"hello"), encode(2, 10, b"ACK:hello"), b"BAD!" + encode(1, 11, b"x")[4:],
                HEADER.pack(MAGIC, 1, 1, 12, 20) + b"x", HEADER.pack(MAGIC, 1, 99, 13, 0), MAGIC + b"x"]
    path = evidence_dir / "offline_labdemo.pcap"
    with PcapFile.writer(path, 1) as writer:
        for index, payload in enumerate(payloads, 1):
            data = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.1", dst="192.0.2.2")/UDP(sport=40000, dport=45990)/Raw(payload))
            writer.append(RawPacket(index, 1_790_000_000_000_000_000 + index * 1_000_000, data, len(data), 1))
    rows, result = table(["-r", path], ["frame.number", "labdemo.type", "labdemo.request_id", "labdemo.valid", "labdemo.error"])
    assert rows[0][1:4] == ["1", "10", "True"]
    assert rows[1][1:4] == ["2", "10", "True"]
    assert rows[2][1:] == ["", "", "", ""]
    assert rows[3][3:] == ["False", "invalid_length"]
    assert rows[4][3:] == ["False", "unknown_type"]
    assert rows[5][3:] == ["False", "header_truncated"]
    filtered, _ = table(["-r", path, "-Y", "labdemo.type == 1 && labdemo.valid == 1"], ["labdemo.request_id"])
    assert filtered == [["10"]]
    (evidence_dir / "lua_demo_fields.csv").write_text(result.stdout, encoding="utf-8")


@pytest.mark.wireshark
def test_pid_plugin_real_metadata_pairing(evidence_dir):
    record_path = evidence_dir / "tcp_pid_18080.json"
    if not record_path.exists():
        pytest.skip("需要先执行真实 TCP/PID 测试生成本次机器的证据")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    path = Path(record["pcap"])
    metadata = load_metadata(path)
    preferences = ["-o", f"labproc.metadata:{path}.labproc.json", "-o", f"labproc.capture:{path}"]
    args = ["-2", "-R", "frame.number >= 1", "-r", path, *preferences]
    rows, result = table(args, ["frame.number", "labproc.pid", "labproc.name", "labproc.status", "labproc.original_number"])
    expected = [index for index, item in enumerate(metadata["packets"], 1) if item["process"]["owners"]]
    actual = [int(row[0]) for row in rows if row[1]]
    assert actual == expected, rows
    assert all(str(record["pid"]) in row[1].split(",") for row in rows if row[1])
    filtered, _ = table(args + ["-Y", f"labproc.pid == {record['pid']}"], ["frame.number"])
    assert [int(row[0]) for row in filtered] == expected
    repeated, _ = table(args, ["frame.number", "labproc.pid", "labproc.name", "labproc.status", "labproc.original_number"])
    assert rows == repeated
    unknown, _ = table(["-2", "-R", "frame.number >= 1", "-r", path], ["labproc.pid", "labproc.status"])
    assert all(row == ["", "unknown_no_metadata"] for row in unknown)
    altered = evidence_dir / "changed_capture.pcap"
    packets = list(PcapFile.read(path))
    with PcapFile.writer(altered, packets[0].linktype) as writer:
        for packet in packets[1:]:
            writer.append(packet)
    mismatch, _ = table(["-2", "-R", "frame.number >= 1", "-r", altered, *preferences], ["labproc.pid", "labproc.status"])
    assert all(not row[0] for row in mismatch)
    assert any(row[1] == "pairing_mismatch" for row in mismatch)
    stale, _ = table(["-2", "-R", "frame.number >= 1", "-r", altered, "-o", f"labproc.metadata:{path}.labproc.json", "-o", f"labproc.capture:{altered}"], ["labproc.pid", "labproc.status"])
    assert all(not row[0] and "capture_hash_mismatch" in row[1] for row in stale)
    (evidence_dir / "lua_pid_fields.csv").write_text(result.stdout, encoding="utf-8")


@pytest.mark.live
@pytest.mark.wireshark
def test_real_demo_request_response_listener(evidence_dir):
    loopback = next(device.name for device in Npcap().devices() if "Loopback" in device.name)
    engine = CaptureEngine(evidence_dir, CaptureConfig(loopback, "udp port 45990"), parser=parse_packet)
    engine.start()
    try:
        assert engine.ready.wait(5)
        assert not engine.error
        with DemoServer() as server:
            results = exercise(port=server.port)
        time.sleep(0.1)
    finally:
        engine.stop()
        engine.wait(5)
    assert not engine.error, engine.error
    path = engine.directory / "capture.pcap"
    result = tshark(["-r", path, "-q"], ("labdemo.lua", "labdemo_stats.lua"))
    assert "requests=3 responses=3 pairs=2 errors=1 invalid=2" in result.stdout, result.stdout
    assert "timeout=1" in result.stdout
    (evidence_dir / "lua_listener.txt").write_text(result.stdout, encoding="utf-8")
    (evidence_dir / "real_demo.json").write_text(json.dumps({"pcap": str(path), "results": results}, ensure_ascii=False, indent=2), encoding="utf-8")
