from datetime import datetime

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QComboBox, QDialog, QHBoxLayout, QPushButton, QPlainTextEdit,
                               QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout)

from .ui import ASSOCIATIONS, STATES, apply_theme, card, endpoint, heading, size_text


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
    if direction["capture_truncated"]:
        parts.append("[此方向包含捕获截断包；未保存的内容无法恢复]")
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
        apply_theme(self)
        self.resize(1160, 780)
        self.setMinimumSize(880, 580)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)
        ends = flow["endpoints"]
        header = QHBoxLayout()
        header.addWidget(heading(f"TCP 流 {flow['id']}", "title"))
        header.addStretch()
        badge = heading(STATES.get(flow["state"], flow["state"]), "badge")
        header.addWidget(badge)
        layout.addLayout(header)
        endpoints, endpoint_layout = card()
        endpoint_layout.addWidget(heading(f"A   {endpoint(ends[0])}"))
        endpoint_layout.addWidget(heading(f"B   {endpoint(ends[1])}"))
        started = datetime.fromtimestamp(flow["started"] / 1e9).strftime("%H:%M:%S.%f")
        duration = (flow["ended"] - flow["started"]) / 1e9
        endpoint_layout.addWidget(heading(f"开始 {started}  ·  持续 {duration:.3f} s  ·  包数 A / B：{flow['packets'][0]} / {flow['packets'][1]}", "hint"))
        layout.addWidget(endpoints)
        toolbar = QHBoxLayout()
        incomplete = any(direction["incomplete"] for direction in flow["directions"])
        toolbar.addWidget(heading("内容存在不完整标记，请查看方向内的说明。" if incomplete else "按 TCP 序号重组的双向内容", "hint"), 1)
        toolbar.addWidget(heading("内容格式", "hint"))
        self.content_format = QComboBox()
        self.content_format.addItems(["文本", "十六进制"])
        toolbar.addWidget(self.content_format)
        layout.addLayout(toolbar)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.editors = []
        for direction, title in enumerate(("A → B", "B → A")):
            editor = QPlainTextEdit()
            editor.setReadOnly(True)
            editor.setFont(QFont("Consolas", 11))
            editor.setLineWrapMode(QPlainTextEdit.NoWrap)
            editor.setPlainText(direction_text(flow["directions"][direction]))
            self.editors.append(editor)
            self.tabs.addTab(editor, f"{title}  {size_text(len(flow['directions'][direction]['data']))}")

        def change_format(index):
            for direction, editor in enumerate(self.editors):
                editor.setPlainText(direction_text(flow["directions"][direction], index == 1))

        self.content_format.currentIndexChanged.connect(change_format)
        self.timeline = QTreeWidget()
        self.timeline.setHeaderLabels(["相对时间", "包编号", "方向", "事件", "TCP 序号", "载荷字节"])
        self.timeline.setRootIsDecorated(False)
        self.timeline.setAlternatingRowColors(True)
        for column, width in enumerate((130, 90, 100, 180, 160, 110)):
            self.timeline.setColumnWidth(column, width)
        for event in flow["events"]:
            relative = (event["timestamp_ns"] - flow["started"]) / 1e9
            self.timeline.addTopLevelItem(QTreeWidgetItem([f"{relative:.6f} s", str(event["number"]),
                "A → B" if event["direction"] == 0 else "B → A", event["event"], str(event["sequence"]), str(event["payload_length"])]))
        if flow["events_dropped"]:
            self.timeline.insertTopLevelItem(0, QTreeWidgetItem(["窗口提示", "", "", f"较早 {flow['events_dropped']} 个事件已淘汰"]))
        self.tabs.addTab(self.timeline, "连接时间线")
        self.http_tree = QTreeWidget()
        self.http_tree.setHeaderLabels(["方向 / 消息 / 字段", "内容"])
        self.http_tree.setColumnWidth(0, 310)
        self.http_tree.setAlternatingRowColors(True)
        for direction, messages in enumerate(flow["http"]):
            parent_item = QTreeWidgetItem(["A → B" if direction == 0 else "B → A", f"{len(messages)} 个 HTTP 消息"])
            self.http_tree.addTopLevelItem(parent_item)
            for message in messages:
                title = (f"{message['method']} {message['path']}" if "method" in message
                         else f"HTTP/{message['version']} {message['status']} {message.get('reason', '')}")
                item = QTreeWidgetItem(parent_item, [title, message["body_state"]])
                QTreeWidgetItem(item, ["HTTP 版本", message["version"]])
                QTreeWidgetItem(item, ["Host", message.get("host", "")])
                headers = QTreeWidgetItem(item, ["头部", f"{len(message['headers'])} 个字段"])
                for name, values in message["headers"].items():
                    QTreeWidgetItem(headers, [name, "; ".join(values)])
                QTreeWidgetItem(item, ["正文预览", message["body_preview"]])
                QTreeWidgetItem(item, ["重组状态", "存在不完整标记" if message.get("reassembly_incomplete") else "连续区间"])
        self.http_tree.expandToDepth(1)
        self.tabs.addTab(self.http_tree, "HTTP 消息")
        self.process_tree = QTreeWidget()
        self.process_tree.setHeaderLabels(["进程 / 观察字段", "实际值"])
        self.process_tree.setColumnWidth(0, 310)
        self.process_tree.setAlternatingRowColors(True)
        self.process_tree.addTopLevelItem(QTreeWidgetItem(["关联状态", " / ".join(ASSOCIATIONS.get(value, value) for value in flow["association_statuses"])]))
        if not flow["owners"]:
            self.process_tree.addTopLevelItem(QTreeWidgetItem(["进程未知", "未获得可用的本机进程关联证据"]))
        for owner in flow["owners"]:
            item = QTreeWidgetItem([f"PID {owner['pid']}  ·  {owner['name']}", owner.get("local", "")])
            self.process_tree.addTopLevelItem(item)
            for name, key in (("本地端点", "local"), ("远端端点", "remote"), ("采样开始（ns）", "sample_started_ns"), ("采样结束（ns）", "sample_ns")):
                QTreeWidgetItem(item, [name, str(owner.get(key, "未知"))])
            QTreeWidgetItem(item, ["进程创建时间", datetime.fromtimestamp(owner["created"]).isoformat(sep=" ", timespec="milliseconds")])
        self.process_tree.expandToDepth(0)
        self.tabs.addTab(self.process_tree, "本机进程")
        layout.addWidget(self.tabs, 1)
        footer = QHBoxLayout()
        footer.addWidget(heading("进程信息为捕获时的历史观察；未知状态保留原始含义。", "hint"), 1)
        if parent is not None:
            packets_button = QPushButton("查看此流的数据包")
            def show_packets():
                parent.set_filter(f"tcp.stream == {flow['id']}")
                parent.workspace_tabs.setCurrentIndex(0)
                self.accept()
            packets_button.clicked.connect(show_packets)
            footer.addWidget(packets_button)
        close_button = QPushButton("关闭")
        close_button.setObjectName("primary")
        close_button.clicked.connect(self.accept)
        footer.addWidget(close_button)
        layout.addLayout(footer)
