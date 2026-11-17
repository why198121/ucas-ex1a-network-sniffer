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
from labsniffer.cli import find_wireshark


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
    video = json.loads((ROOT / "output/video/latest.json").read_text(encoding="utf-8"))
    if video["status"] != "PASS" or hashlib.sha256(Path(video["video"]).read_bytes()).hexdigest() != video["video_sha256"]:
        raise RuntimeError("视频验收或文件摘要检查失败")
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
    shutil.copy2(video["video"], top / Path(video["video"]).name)
    materials = top / "后期配音素材"
    materials.mkdir()
    for key, name in (("clean_video", "无字幕素材.mp4"), ("subtitles", "演示字幕.srt"),
                      ("voiceover", "配音稿.txt"), ("mapping", "镜头与PDF对应表.md")):
        shutil.copy2(video[key], materials / name)
    video_evidence = source / "evidence/video"
    video_evidence.mkdir()
    video_directory = Path(video["directory"])
    for name in ("recording-result.json", "video-check.json", "events.json", "traffic.json", "ffprobe.json",
                 "capture-ffmpeg.log", "subtitle-render.log", "decode.log", "black-detection.log", "pid-fields.json",
                 "tshark-fields.csv", "tshark-verification.json",
                 "demo_capture.pcap", "demo_capture.pcap.labproc.json"):
        shutil.copy2(video_directory / name, video_evidence / name)
    for path in video_directory.glob("ui-*.json"):
        shutil.copy2(path, video_evidence / path.name)
    environment = json.loads((acceptance / "environment.json").read_text(encoding="utf-8"))
    locations = ["本机文件位置说明", "以下绝对路径对应生成交付包的电脑；移动或解压到其他位置后，请使用相同目录中的文件。", "",
                 f"Wireshark：{find_wireshark('Wireshark.exe')}", f"TShark：{find_wireshark('tshark.exe')}",
                 f"Npcap DLL：{environment['npcap']['dll']}", f"开发工程：{ROOT}",
                 f"启动嗅探器：{ROOT / 'start.ps1'}", f"加载课程插件：{ROOT / 'open_wireshark.ps1'}", "",
                 f"提交 ZIP：{destination / (outer_name + '.zip')}", f"交付源码：{source}",
                 f"带字幕视频：{top / Path(video['video']).name}", f"实验报告：{top / report.name}",
                 f"无字幕素材：{materials / '无字幕素材.mp4'}", f"独立字幕：{materials / '演示字幕.srt'}",
                 f"配音稿：{materials / '配音稿.txt'}", f"镜头对应表：{materials / '镜头与PDF对应表.md'}", "",
                 f"本次抓包：{video_evidence / 'demo_capture.pcap'}",
                 f"本次 PID 元数据：{video_evidence / 'demo_capture.pcap.labproc.json'}",
                 f"Lua 插件：{source / 'wireshark'}", f"完整验收记录：{source / 'evidence/acceptance'}",
                 f"视频检查记录：{video_evidence / 'video-check.json'}", "",
                 "姓名、学号和真实远程仓库地址保留明确占位；视频没有配音，可使用配音稿与字幕完成后期录音。"]
    (top / "文件位置说明.txt").write_text("\n".join(locations) + "\n", encoding="utf-8-sig")
    python_files = list(source.rglob("*.py"))
    for path in python_files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    check = {"status": "PASS", "git_head": git("rev-parse", "HEAD").strip(), "acceptance_run": result["run_id"],
             "tests": result["counts"], "python_files_syntax_checked": len(python_files), "samples_checked": manifest,
             "report_check": json.loads((ROOT / "output/report/report-check.json").read_text(encoding="utf-8")),
             "video_check": video, "uncompleted": ["真实姓名与学号", "真实远程仓库 URL"],
             "scope": "源码语法、样例 PCAP 读取、配套摘要、报告内容检查、实际录屏与字幕、ZIP CRC"}
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
                    f"{outer_name}/{report.name}", f"{outer_name}/{Path(video['video']).name}",
                    f"{outer_name}/后期配音素材/演示字幕.srt", f"{outer_name}/后期配音素材/配音稿.txt"]
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
