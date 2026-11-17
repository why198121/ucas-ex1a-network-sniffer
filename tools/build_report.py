import json
import importlib.metadata
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape

from pypdf import PdfReader
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)


ROOT = Path(__file__).resolve().parents[1]
WIDTH = A4[0] - 92
FONT = "ReportChinese"


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    latest = json.loads((ROOT / "output/acceptance/latest.json").read_text(encoding="utf-8"))
    evidence_dir = Path(latest["directory"])
    results = json.loads((evidence_dir / "results.json").read_text(encoding="utf-8"))
    if results["exit_code"] != 0 or results["counts"].get("FAIL", 0):
        raise RuntimeError("正式验收存在失败，不能生成交付报告")
    environment = json.loads((evidence_dir / "environment.json").read_text(encoding="utf-8"))
    pdfmetrics.registerFont(TTFont(FONT, "C:/Windows/Fonts/msyh.ttc", subfontIndex=0))
    styles = {
        "para": ParagraphStyle("正文", fontName=FONT, fontSize=9.3, leading=15, spaceAfter=7, wordWrap="CJK", splitLongWords=True),
        "title": ParagraphStyle("标题", fontName=FONT, fontSize=23, leading=32, spaceAfter=14, alignment=TA_CENTER),
        "subtitle": ParagraphStyle("副标题", fontName=FONT, fontSize=11, leading=18, spaceAfter=20, alignment=TA_CENTER),
        "heading": ParagraphStyle("章节", fontName=FONT, fontSize=14, leading=22, spaceBefore=15, spaceAfter=9, keepWithNext=True),
        "cell": ParagraphStyle("表格", fontName=FONT, fontSize=8, leading=12, wordWrap="CJK", splitLongWords=True),
        "code": ParagraphStyle("命令", fontName=FONT, fontSize=8.2, leading=13, backColor=colors.HexColor("#F0F3F7"),
                               borderPadding=7, spaceAfter=12, wordWrap="CJK", splitLongWords=True),
    }

    def paragraph(text, style="para"):
        return Paragraph(escape(str(text)).replace("\n", "<br/>"), styles[style])

    def table(rows, widths):
        data = [[paragraph(value, "cell") for value in row] for row in rows]
        item = Table(data, colWidths=[WIDTH * part for part in widths], repeatRows=1, hAlign="LEFT")
        item.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DDE8F2")),
                                 ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F6F8FA")]),
                                 ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CCD5DF")),
                                 ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                                 ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        return [item, Spacer(1, 10)]

    story = []

    def render(element):
        if element.tag in ("title", "subtitle", "para", "code"):
            story.append(paragraph(element.text or "", element.tag))
        elif element.tag == "section":
            story.append(paragraph(element.attrib["title"], "heading"))
            for child in element:
                render(child)
        elif element.tag == "table":
            story.extend(table([[cell.text or "" for cell in row] for row in element],
                               [float(part) for part in element.attrib["widths"].split(",")]))
        elif element.tag == "environment":
            rows = [["项目", "实际记录"], ["运行日期", environment["time"]], ["操作系统", environment["os"]],
                    ["Python", environment["python"]], ["位数", environment["bits"]],
                    ["Npcap", environment.get("npcap", {}).get("version", "本次未验证")],
                    ["枚举网卡数", len(environment.get("npcap", {}).get("devices", []))]]
            rows.extend([[name, version] for name, version in environment["dependencies"].items()])
            version_file = evidence_dir / "tshark-version.txt"
            if version_file.exists():
                rows.append(["TShark", version_file.read_text(encoding="utf-8").splitlines()[0]])
            story.extend(table(rows, [0.28, 0.72]))
        elif element.tag == "acceptance":
            story.append(paragraph(f"运行编号：{results['run_id']}；{results['counts']}；实际测试耗时 {results['duration_seconds']:.3f} 秒。日志位于源码 evidence/acceptance，以下结果来自本次 junit.xml。"))
            rows = [["实际测试", "状态", "秒数"]]
            rows.extend([[item["test"].removeprefix("tests."), item["status"], f"{item['seconds']:.3f}"] for item in results["tests"]])
            story.extend(table(rows, [0.76, 0.12, 0.12]))
        elif element.tag == "evidence":
            base = evidence_dir / "evidence"
            gui = json.loads((base / "gui_sustained.json").read_text(encoding="utf-8"))
            nps = json.loads((base / "nps_live.json").read_text(encoding="utf-8"))
            child = json.loads((base / "child_exit.json").read_text(encoding="utf-8"))
            comparison = json.loads((base / "field_comparison.json").read_text(encoding="utf-8"))
            story.append(paragraph(f"空闲停止两次实测延迟为 {nps[0]['stop_seconds']:.4f} / {nps[1]['stop_seconds']:.4f} 秒。持续 GUI 测试发送并保存 {gui['generated']} 个 UDP 包，BPF 排除 {gui['excluded_by_bpf']} 个其他端口包；事件计时器触发 {gui['heartbeat_ticks']} 次，最大间隔 {gui['max_heartbeat_gap_seconds']:.4f} 秒。"))
            stats = gui["stats"]
            story.append(paragraph(f"该持续测试实际捕获 {stats['captured']} 包 / {stats['bytes']} 字节，驱动丢包 {stats['driver_drops']}，采集队列丢弃 {stats['capture_queue_drops']}，GUI 队列丢弃 {stats['gui_queue_drops']}，接口丢包未知。使用显示过滤 tcp 后显示零包，后台导出的 PCAP 仍包含全部 {gui['generated']} 个 UDP 包。"))
            story.append(paragraph(f"实际退出测试的流量进程 PID={child['pid']}，启动器 PID={child['launcher_pid']}；观察到 {len(child['flows'])} 条 TCP 流，退出码 {child['exit_code']}，退出后活动连接 {child['active_connections_after_exit']}。历史 PID 元数据保留。"))
            story.append(paragraph((base / "lua_listener.txt").read_text(encoding="utf-8").strip(), "code"))
            navigation_path = base / "gui_navigation.json"
            if navigation_path.exists():
                navigation = json.loads(navigation_path.read_text(encoding="utf-8"))
                story.extend(table([["实际窗口尺寸", "数据包可视高度", "TCP 流可视高度"]] +
                                   [[" × ".join(map(str, item["window"])), item["packet_viewport_height"], item["flow_viewport_height"]]
                                    for item in navigation["measurements"]], [0.40, 0.30, 0.30]))
            story.extend(table([["同文件对照", "包数", "结果", "TShark 解码设置"]] +
                               [[item["source"], item["packets_compared"], item["status"], item["decode_as"] or "默认"] for item in comparison],
                               [0.30, 0.12, 0.12, 0.46]))
        elif element.tag == "history":
            output = subprocess.run(["git", "log", "--reverse", "--format=%h | %aI | %an | %s"], cwd=ROOT,
                                    check=True, capture_output=True, encoding="utf-8").stdout
            for line in output.splitlines():
                story.append(paragraph(line))
        else:
            raise ValueError(f"报告中存在未处理的 XML 元素：{element.tag}")

    for element in ET.parse(ROOT / "docs/report.xml").getroot():
        render(element)
    destination = ROOT / "output/report"
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "姓名待填写_学号待填写_ex1A_report.pdf"

    def footer(canvas, document):
        canvas.setFont(FONT, 8)
        canvas.setFillColor(colors.HexColor("#526175"))
        canvas.drawString(46, 25, "实验 1A · 实际证据与实现说明")
        canvas.drawRightString(A4[0] - 46, 25, f"{document.page}")

    document = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=46, leftMargin=46, topMargin=40, bottomMargin=44,
                                 title="实验 1A：带 GUI 的网络嗅探器", author="姓名待填写；AI 辅助实现")
    document.build(story, onFirstPage=footer, onLaterPages=footer)
    reader = PdfReader(path)
    text = "\n".join(page.extract_text() for page in reader.pages)
    terms = ["课程要求", "GetExtendedTcpTable", "labproc.pid", "Content-Length", "未验证", "尚未录制", "待填写", results["run_id"]]
    missing = [term for term in terms if term not in text]
    if missing or any(float(page.mediabox.width) > 600 or float(page.mediabox.height) > 850 for page in reader.pages):
        raise RuntimeError(f"PDF 内容或尺寸检查失败：{missing}")
    if any(not page.extract_text().strip() for page in reader.pages):
        raise RuntimeError("PDF 中存在空白页")
    check = {"status": "PASS", "file": str(path), "pages": len(reader.pages), "text_characters": len(text),
             "required_terms": terms, "font": "Microsoft YaHei embedded", "visual_check": "未执行：用户禁止主动视觉检查"}
    check["report_runtime"] = {"python": sys.version, "reportlab": importlib.metadata.version("reportlab"),
                               "pypdf": importlib.metadata.version("pypdf")}
    (destination / "report-check.json").write_text(json.dumps(check, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(check, ensure_ascii=False))


if __name__ == "__main__":
    main()
