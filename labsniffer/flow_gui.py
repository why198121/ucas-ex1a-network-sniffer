import json
from datetime import datetime

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QPlainTextEdit, QTabWidget, QVBoxLayout


def bytes_text(data, hexadecimal=False):
    if not hexadecimal:
        return data.decode("utf-8", errors="replace")
    return "\n".join(f"{offset:08x}  {data[offset:offset + 16].hex(' ')}" for offset in range(0, len(data), 16))


def direction_text(direction, hexadecimal=False):
    parts = []
    if direction["missing_prefix"]:
        parts.append("[未观察到 SYN；流起点可能缺失]")
    if direction["limited"]:
        parts.append("[重组达到内存限制；内容不完整]")
    if direction["conflict_bytes"]:
        parts.append(f"[重叠冲突 {direction['conflict_bytes']} 字节；保留首次观察值]")
    cursor = 0 if not direction["missing_prefix"] else (direction["segments"][0][0] if direction["segments"] else 0)
    for start, value in direction["segments"]:
        if start > cursor:
            parts.append(f"[缺口：相对序号 {cursor}–{start}，缺少 {start - cursor} 字节]")
        parts.append(f"[相对序号 {start}，长度 {len(value)}]\n" + bytes_text(value, hexadecimal))
        cursor = start + len(value)
    for left, right in direction["gaps"]:
        if left >= cursor:
            parts.append(f"[尾部缺口：相对序号 {left}–{right}]")
    if not parts:
        parts.append("未观察到此方向的应用数据")
    return "\n\n".join(parts)


class FlowDialog(QDialog):
    def __init__(self, flow, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"追踪 TCP 流 {flow['id']}")
        self.resize(1100, 760)
        layout = QVBoxLayout(self)
        ends = flow["endpoints"]
        layout.addWidget(QLabel(f"A {ends[0]}  ↔  B {ends[1]}   状态 {flow['state']}"))
        tabs = QTabWidget()
        for direction, title in enumerate(("A → B", "B → A")):
            for hexadecimal, mode in ((False, "文本"), (True, "十六进制")):
                editor = QPlainTextEdit()
                editor.setReadOnly(True)
                editor.setFont(QFont("Consolas", 10))
                editor.setPlainText(direction_text(flow["directions"][direction], hexadecimal))
                tabs.addTab(editor, f"{title} {mode}")
        timeline = QPlainTextEdit()
        timeline.setReadOnly(True)
        lines = []
        for event in flow["events"]:
            relative = (event["timestamp_ns"] - flow["started"]) / 1e9
            lines.append(f"{relative:.6f}s  包 {event['number']}  {'A → B' if event['direction'] == 0 else 'B → A'}  "
                         f"{event['event']}  Seq={event['sequence']}  应用字节={event['payload_length']}")
        if flow["events_dropped"]:
            lines.insert(0, f"[较早的 {flow['events_dropped']} 个事件已从内存窗口淘汰]")
        timeline.setPlainText("\n".join(lines))
        tabs.addTab(timeline, "连接时间线")
        metadata = QPlainTextEdit()
        metadata.setReadOnly(True)
        metadata.setPlainText(json.dumps({"owners": flow["owners"], "statuses": flow["association_statuses"], "http": flow["http"]}, ensure_ascii=False, indent=2))
        tabs.addTab(metadata, "进程与 HTTP")
        layout.addWidget(tabs)
        close_button = QPushButton("关闭")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)
