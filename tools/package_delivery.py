import ast
import hashlib
import json
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from labsniffer.storage import PcapFile, load_metadata


def git(*arguments):
    return subprocess.run(["git", *arguments], cwd=ROOT, check=True, capture_output=True, encoding="utf-8").stdout


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    changes = git("diff", "--name-only") + git("diff", "--cached", "--name-only")
    if changes.strip():
        raise RuntimeError("存在尚未提交的已跟踪变更，请先保留真实开发记录")
    current = json.loads((ROOT / "output/acceptance/latest.json").read_text(encoding="utf-8"))
    acceptance = Path(current["directory"])
    result = json.loads((acceptance / "results.json").read_text(encoding="utf-8"))
    if result["exit_code"] != 0:
        raise RuntimeError("验收存在失败，停止打包")
    outer_name = "姓名待填写_学号待填写_EX1A"
    source_name = "姓名待填写_学号待填写_ex1A_src"
    destination = ROOT / "dist" / time.strftime("delivery_%Y%m%d_%H%M%S")
    top = destination / outer_name
    source = top / source_name
    source.mkdir(parents=True, exist_ok=False)
    files = git("-c", "core.quotepath=false", "ls-files", "-z").split("\0")
    for name in files:
        if not name:
            continue
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    git("bundle", "create", str(source / "git-history.bundle"), "--all")
    (source / "git-history.txt").write_text(git("log", "--reverse", "--format=%h %aI %an %s"), encoding="utf-8")
    shutil.copytree(acceptance, source / "evidence/acceptance")
    samples = source / "samples"
    samples.mkdir()
    manifest = []
    evidence = acceptance / "evidence"
    mapping = {"tcp_pid_18080": "real_http_18080", "tcp_pid_18081": "real_http_ipv6_18081", "tcp_pid_80": "real_http_80",
               "child_exit": "real_child_exit", "gui_sustained": "real_gui_udp", "dns_icmp": "real_dns_icmp", "real_demo": "real_labdemo"}
    selections = []
    for record_name, sample_name in mapping.items():
        record = json.loads((evidence / f"{record_name}.json").read_text(encoding="utf-8"))
        selections.append((Path(record["pcap"]), sample_name, "真实本机网络", f"{record_name}.json"))
    for name in ("offline_labdemo", "offline_tcp_gap_retransmission"):
        selections.append((evidence / f"{name}.pcap", name, "人工构造的离线边界样本", "pytest.log"))
    for original, name, kind, record in selections:
        target = samples / f"{name}.pcap"
        shutil.copy2(original, target)
        sidecar = Path(str(original) + ".labproc.json")
        if sidecar.exists():
            shutil.copy2(sidecar, Path(str(target) + ".labproc.json"))
        packets = list(PcapFile.read(target))
        metadata = load_metadata(target)
        manifest.append({"file": target.name, "source": kind, "evidence_record": record, "packets": len(packets),
                         "pid_metadata": metadata is not None, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    (samples / "样例清单.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    report = ROOT / "output/report/姓名待填写_学号待填写_ex1A_report.pdf"
    shutil.copy2(report, top / report.name)
    shutil.copy2(ROOT / "output/report/report-check.json", source / "evidence/report-check.json")
    (top / "视频尚未完成.txt").write_text(
        "演示视频尚未录制。录制操作与讲解稿位于源码 docs/录制步骤与答辩.md。\n"
        "请实际运行并录制，完整播放检查后保存为 姓名_学号_ex1A_play.mp4。\n"
        "提交前填写真实姓名、学号和远程 Git 仓库地址，重新生成报告与 ZIP。\n", encoding="utf-8")
    python_files = list(source.rglob("*.py"))
    for path in python_files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    check = {"status": "PASS", "git_head": git("rev-parse", "HEAD").strip(), "acceptance_run": result["run_id"],
             "tests": result["counts"], "python_files_syntax_checked": len(python_files), "samples_checked": manifest,
             "report_check": json.loads((ROOT / "output/report/report-check.json").read_text(encoding="utf-8")),
             "uncompleted": ["真实姓名与学号", "真实远程仓库 URL", "实际演示 MP4"],
             "scope": "源码语法、样例 PCAP 读取、配套摘要、报告内容检查、ZIP CRC"}
    (source / "evidence/delivery-check.json").write_text(json.dumps(check, ensure_ascii=False, indent=2), encoding="utf-8")
    output = destination / f"{outer_name}.zip"
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(top.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(destination))
    with zipfile.ZipFile(output) as archive:
        corrupt = archive.testzip()
        if corrupt:
            raise RuntimeError(f"ZIP CRC 检查失败：{corrupt}")
        required = [f"{outer_name}/{source_name}/labsniffer/gui.py", f"{outer_name}/{source_name}/wireshark/labproc.lua",
                    f"{outer_name}/{report.name}", f"{outer_name}/视频尚未完成.txt"]
        if any(name not in archive.namelist() for name in required):
            raise RuntimeError("ZIP 缺少必要交付文件")
        count = len(archive.namelist())
    summary = {"zip": str(output), "source": str(source), "files": count, "size": output.stat().st_size,
               "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "status": "PASS"}
    (destination / "delivery-check.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / "dist/latest.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
