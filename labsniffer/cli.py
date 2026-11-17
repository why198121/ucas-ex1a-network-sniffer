import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .capture import CaptureEngine
from .npcap import CaptureConfig, Npcap
from .processes import ProcessTracker
from .protocols import parse_packet
from .storage import PcapFile, export_session, load_metadata
from .streams import StreamManager


ROOT = Path(__file__).resolve().parents[1]


def find_wireshark(name):
    configured = os.environ.get("TSHARK_PATH" if name == "tshark.exe" else "WIRESHARK_PATH")
    candidates = [Path(configured)] if configured else []
    candidates += [Path("C:/Program Files/Wireshark") / name, ROOT / ".work/WiresharkPortable64/App/Wireshark" / name]
    if shutil.which(name):
        candidates.append(Path(shutil.which(name)))
    for path in candidates:
        if path.is_file():
            return path
    raise FileNotFoundError(f"找不到 {name}；请安装 Wireshark 或设置对应环境变量")


def wireshark_arguments(path, gui=False):
    path = Path(path).resolve()
    metadata = load_metadata(path)
    executable = find_wireshark("Wireshark.exe" if gui else "tshark.exe")
    command = [str(executable)]
    if not gui:
        command += ["-2", "-R", "frame.number >= 1"]
    for script in ("labdemo.lua", "labproc.lua", "labdemo_stats.lua"):
        command += ["-X", f"lua_script:{ROOT / 'wireshark' / script}"]
    command += ["-r", str(path)]
    if metadata:
        command += ["-o", f"labproc.metadata:{path}.labproc.json", "-o", f"labproc.capture:{path}"]
    return command


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="实验 1A 命令行采集和校验入口")
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("devices")
    capture = subparsers.add_parser("capture")
    capture.add_argument("--interface", required=True)
    capture.add_argument("--bpf", default="")
    capture.add_argument("--seconds", type=float, default=10)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--snaplen", type=int, default=65535)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("pcap", type=Path)
    wireshark = subparsers.add_parser("wireshark")
    wireshark.add_argument("pcap", type=Path)
    wireshark.add_argument("--gui", action="store_true")
    args = parser.parse_args()
    if args.action == "devices":
        api = Npcap()
        print(api.version)
        for device in api.devices():
            print(json.dumps({"name": device.name, "description": device.description, "addresses": device.addresses}, ensure_ascii=False))
    elif args.action == "capture":
        if not 0 < args.seconds <= 3600:
            parser.error("seconds 范围为 0–3600")
        tracker, flows = ProcessTracker(), StreamManager()
        tracker.start()
        engine = CaptureEngine(ROOT / "output/sessions", CaptureConfig(args.interface, args.bpf, args.snaplen),
                               parser=parse_packet, analyzer=flows, process_tracker=tracker)
        engine.start()
        try:
            engine.ready.wait(10)
            end = time.monotonic() + args.seconds
            while time.monotonic() < end and not engine.error:
                time.sleep(0.05)
        except KeyboardInterrupt:
            pass
        finally:
            engine.stop()
            engine.wait(10)
            tracker.stop()
        print(json.dumps(engine.snapshot(), ensure_ascii=False, indent=2))
        if engine.error:
            raise RuntimeError(engine.error)
        export_session(engine.directory, args.output)
    elif args.action == "inspect":
        metadata = load_metadata(args.pcap)
        flows = StreamManager()
        count = 0
        for raw in PcapFile.read(args.pcap):
            packet = parse_packet(raw)
            flows.add(packet)
            count += 1
            print(json.dumps({"number": raw.number, "protocol": packet.protocol, "src": packet.src, "dst": packet.dst,
                              "sport": packet.sport, "dport": packet.dport, "summary": packet.summary}, ensure_ascii=False))
        print(json.dumps({"packets": count, "tcp_streams": len(flows.snapshot()), "metadata": metadata is not None}))
    else:
        command = wireshark_arguments(args.pcap, args.gui)
        if args.gui:
            subprocess.Popen(command)
        else:
            subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
