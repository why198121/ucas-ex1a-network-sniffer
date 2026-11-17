import argparse
import ctypes
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from labsniffer.cli import find_wireshark
from labsniffer.npcap import Npcap


def command_record(arguments, destination):
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, encoding="utf-8", errors="replace", timeout=30)
    destination.write_text(result.stdout + "\nSTDERR:\n" + result.stderr, encoding="utf-8")
    return {"command": list(map(str, arguments)), "exit_code": result.returncode, "log": destination.name}


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    run_id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
    destination = ROOT / "output/acceptance" / run_id
    destination.mkdir(parents=True)
    evidence = destination / "evidence"
    evidence.mkdir()
    environment = os.environ.copy()
    environment["LAB_EVIDENCE_DIR"] = str(evidence)
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    info = {"run_id": run_id, "time": time.strftime("%Y-%m-%d %H:%M:%S %z"), "python": sys.version,
            "executable": sys.executable, "os": platform.platform(), "bits": ctypes.sizeof(ctypes.c_void_p) * 8,
            "dependencies": {name: importlib.metadata.version(name) for name in
                             ("PySide6-Essentials", "shiboken6", "scapy", "lark", "psutil", "pefile", "pytest")},
            "mode": "offline" if args.offline else "full", "observations": []}
    if not args.offline:
        api = Npcap()
        info["npcap"] = {"version": api.version, "dll": api.path,
                         "devices": [{"name": device.name, "description": device.description, "addresses": device.addresses}
                                     for device in api.devices()]}
    try:
        executable = find_wireshark("tshark.exe")
    except FileNotFoundError as error:
        info["observations"].append(str(error))
    else:
        info["tshark"] = command_record([str(executable), "--version"], destination / "tshark-version.txt")
    info["git"] = command_record(["git", "log", "--format=%h %aI %an %s", "-10"], destination / "git-history.txt")
    (destination / "environment.json").write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    tests = ["test_capture_contract", "test_metadata_roundtrip", "test_protocols", "test_filters_http", "test_streams",
             "test_demo", "test_nps_live", "test_processes_live", "test_gui_workflows", "test_wireshark", "test_acceptance_live"]
    command = [sys.executable, "-m", "pytest", *[f"tests/{name}.py" for name in tests], "-q",
               f"--basetemp={ROOT / '.work' / ('pytest-' + run_id)}", f"--junitxml={destination / 'junit.xml'}"]
    if args.offline:
        command += ["-m", "not live and not wireshark and not gui"]
    started = time.monotonic()
    with (destination / "pytest.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace")
        for line in process.stdout:
            print(line, end="", flush=True)
            log.write(line)
        returncode = process.wait()
    results = []
    for case in ET.parse(destination / "junit.xml").iter("testcase"):
        outcome = next((child for child in case if child.tag in ("failure", "error", "skipped")), None)
        status = "PASS" if outcome is None else "SKIP" if outcome.tag == "skipped" else "FAIL"
        results.append({"test": case.attrib.get("classname", "") + "." + case.attrib["name"], "status": status,
                        "seconds": float(case.attrib.get("time", 0)), "reason": "断言通过" if outcome is None else outcome.attrib.get("message", "")})
    summary = {"run_id": run_id, "command": command, "exit_code": returncode, "duration_seconds": time.monotonic() - started,
               "counts": dict(Counter(item["status"] for item in results)), "tests": results,
               "unverified": ["人工视觉审核未执行；视频录制与 Wireshark 菜单演示见 output/video/latest.json 的独立检查记录",
                              "真实网络中的乱序、重传、丢包、PID 复用和权限拒绝未强制制造；相应已覆盖部分见离线测试",
                              "外部 Ethernet 实时流量与高带宽极限性能未测量", "extcap 选做未实现"]}
    if args.offline:
        summary["unverified"].append("本次选择离线模式，实时抓包、GUI 和 Wireshark 检查未执行")
    (destination / "results.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    rows = ["# 验收记录", "", f"实际执行：{info['time']}；运行编号：{run_id}。", "", "| 检查 | 状态 | 秒数 | 判断依据 |", "| --- | --- | ---: | --- |"]
    rows += [f"| {item['test']} | {item['status']} | {item['seconds']:.3f} | {item['reason'].replace('|', '/').replace(chr(10), ' ')} |" for item in results]
    rows += ["", "日志：pytest.log；环境：environment.json；逐包证据：evidence/；结构化结果：results.json。", "", "未验证范围：", ""]
    rows += [f"- {item}" for item in summary["unverified"]]
    (destination / "验收记录.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    (ROOT / "output/acceptance/latest.json").write_text(json.dumps({"directory": str(destination)}, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"results": str(destination), "counts": summary["counts"]}, ensure_ascii=False))
    raise SystemExit(returncode)


if __name__ == "__main__":
    main()
