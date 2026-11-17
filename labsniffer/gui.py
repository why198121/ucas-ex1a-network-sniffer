import logging
import queue
import sys
import threading
import time
from pathlib import Path

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel,
                               QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
                               QSizePolicy, QSpinBox, QSplitter, QTableView, QTabWidget,
                               QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from .capture import CaptureEngine
from .filters import FilterError, compile_filter
from .flow_gui import FlowDialog
from .npcap import CaptureConfig, CaptureError, Npcap
from .processes import ProcessTracker
from .protocols import parse_packet
from .storage import export_session
from .streams import StreamManager
from .ui import ASSOCIATIONS, PROTOCOL_COLORS, STATES, apply_theme, card, endpoint, heading, size_text


ROOT = Path(__file__).resolve().parents[1]


class PacketModel(QAbstractTableModel):
    headers = ["编号", "时间", "源地址", "目的地址", "源端口", "目的端口", "协议", "线上/捕获长度", "摘要"]

    def __init__(self):
        super().__init__()
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        packet = self.rows[index.row()]
        if role == Qt.ToolTipRole:
            return packet.summary + ("\n" + "\n".join(packet.errors) if packet.errors else "")
        if role == Qt.TextAlignmentRole:
            return int(Qt.AlignVCenter | (Qt.AlignRight if index.column() in (0, 4, 5, 7) else Qt.AlignLeft))
        if role in (Qt.BackgroundRole, Qt.ForegroundRole) and index.column() == 6:
            colors = PROTOCOL_COLORS.get(packet.protocol, ("#EEF2F7", "#536780"))
            return QColor(colors[0 if role == Qt.BackgroundRole else 1])
        if role == Qt.ForegroundRole and packet.errors and index.column() == 8:
            return QColor("#AA6637")
        if role != Qt.DisplayRole:
            return None
        raw = packet.raw
        seconds, fraction = divmod(raw.timestamp_ns, 1_000_000_000)
        values = [raw.number, time.strftime("%H:%M:%S", time.localtime(seconds)) + f".{fraction // 1000:06d}",
                  packet.src, packet.dst, packet.sport, packet.dport, packet.protocol,
                  f"{raw.wirelen}/{raw.caplen}", packet.summary or "; ".join(packet.errors)]
        return "" if values[index.column()] is None else str(values[index.column()])

    def replace(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


def hex_view(data):
    lines = []
    for offset in range(0, len(data), 16):
        part = data[offset:offset + 16]
        text = "".join(chr(value) if 32 <= value < 127 else "." for value in part)
        lines.append(f"{offset:08x}  {part.hex(' '):47}  {text}")
    return "\n".join(lines)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UCAS 网络嗅探器 · 实验 1A")
        apply_theme(self)
        self.setMinimumSize(980, 680)
        available = QApplication.primaryScreen().availableGeometry()
        self.resize(min(1440, available.width() - 40), min(940, available.height() - 60))
        self.engine = None
        self.history = []
        self.history_bytes = 0
        self.evicted = 0
        self.display_floor = 0
        self.reported_error = ""
        self.filter_function = lambda packet: True
        self.parser = parse_packet
        self.analyzer = StreamManager()
        self.tracker = None
        self.export_thread = None
        self.export_results = queue.Queue(1)
        self.export_message = ""
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(10)
        self.setCentralWidget(central)
        header = QHBoxLayout()
        title = QVBoxLayout()
        title.setSpacing(2)
        title.addWidget(heading("网络嗅探器", "title"))
        title.addWidget(heading("实时抓包  ·  协议分析  ·  TCP / PID 追踪", "hint"))
        header.addLayout(title)
        header.addStretch()
        self.session_label = heading("未载入会话", "hint")
        header.addWidget(self.session_label)
        self.state_badge = QLabel("未开始")
        self.state_badge.setObjectName("badge")
        header.addWidget(self.state_badge)
        layout.addLayout(header)
        control_card, control_layout = card()
        controls = QHBoxLayout()
        controls.addWidget(heading("网络接口"))
        self.adapters = QComboBox()
        self.adapters.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.adapters.setMinimumContentsLength(28)
        self.adapters.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        controls.addWidget(self.adapters, 1)
        self.refresh_button = QPushButton("刷新网卡")
        controls.addWidget(self.refresh_button)
        self.parameter_button = QToolButton()
        self.parameter_button.setText("过滤与捕获参数")
        self.parameter_button.setCheckable(True)
        self.parameter_button.setArrowType(Qt.RightArrow)
        self.parameter_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        controls.addWidget(self.parameter_button)
        control_layout.addLayout(controls)
        self.start_button = QPushButton("开始新会话")
        self.start_button.setObjectName("primary")
        self.start_button.setShortcut("F5")
        self.start_button.setToolTip("F5 · 创建独立捕获会话")
        self.stop_button = QPushButton("停止")
        self.stop_button.setObjectName("stop")
        self.stop_button.setShortcut("Shift+F5")
        self.clear_button = QPushButton("清空显示")
        self.open_button = QPushButton("打开 PCAP")
        self.open_button.setShortcut("Ctrl+O")
        self.save_button = QPushButton("导出 PCAP + PID")
        self.save_button.setShortcut("Ctrl+S")
        for button in (self.start_button, self.stop_button, self.clear_button):
            controls.addWidget(button)
        header.insertWidget(2, self.open_button)
        header.insertWidget(3, self.save_button)
        capture_filter = QHBoxLayout()
        capture_filter.addWidget(heading("抓包过滤"))
        self.bpf = QLineEdit()
        self.bpf.setClearButtonEnabled(True)
        self.bpf.setPlaceholderText("BPF，例如 tcp or udp port 53；开始抓包前设置")
        capture_filter.addWidget(self.bpf, 1)
        self.parameter_panel = QWidget()
        parameter_layout = QVBoxLayout(self.parameter_panel)
        parameter_layout.setContentsMargins(0, 0, 0, 0)
        parameter_layout.addLayout(capture_filter)
        settings = QHBoxLayout()
        parameter_layout.addLayout(settings)
        self.snaplen = QSpinBox()
        self.snaplen.setRange(64, 262144)
        self.snaplen.setValue(65535)
        self.buffer_mb = QSpinBox()
        self.buffer_mb.setRange(1, 256)
        self.buffer_mb.setValue(8)
        self.timeout_ms = QSpinBox()
        self.timeout_ms.setRange(1, 10000)
        self.timeout_ms.setValue(100)
        self.promiscuous = QCheckBox("混杂模式")
        self.promiscuous.setChecked(True)
        for label, widget in (("捕获字节", self.snaplen), ("缓冲 MiB", self.buffer_mb), ("超时 ms", self.timeout_ms)):
            settings.addWidget(QLabel(label))
            settings.addWidget(widget)
        settings.addWidget(self.promiscuous)
        settings.addStretch()
        self.parameter_panel.hide()
        self.parameter_button.toggled.connect(self.parameter_panel.setVisible)
        self.parameter_button.toggled.connect(lambda checked: self.parameter_button.setArrowType(Qt.DownArrow if checked else Qt.RightArrow))
        control_layout.addWidget(self.parameter_panel)
        layout.addWidget(control_card)
        self.workspace_tabs = QTabWidget()
        self.workspace_tabs.setDocumentMode(True)
        packet_page = QWidget()
        packet_layout = QVBoxLayout(packet_page)
        packet_layout.setContentsMargins(0, 8, 0, 0)
        packet_layout.setSpacing(7)
        display_controls = QHBoxLayout()
        self.display_filter = QLineEdit()
        self.display_filter.setClearButtonEnabled(True)
        self.display_filter.setPlaceholderText('显示过滤，例如 tcp and port == 18080；Ctrl+L 定位')
        self.apply_button = QPushButton("应用显示过滤")
        display_controls.addWidget(heading("显示过滤"))
        display_controls.addWidget(self.display_filter, 1)
        display_controls.addWidget(self.apply_button)
        packet_layout.addLayout(display_controls)
        self.filter_feedback = QLabel()
        self.filter_feedback.setObjectName("feedback")
        self.filter_feedback.hide()
        packet_layout.addWidget(self.filter_feedback)
        self.quick_controls = QHBoxLayout()
        self.quick_buttons = {}
        for label, expression in (("全部", ""), ("HTTP", "http"), ("TCP", "tcp"), ("UDP", "udp"),
                                  ("IPv4", "ipv4"), ("IPv6", "ipv6"), ("ICMP", "icmp or icmpv6"), ("DNS", "dns")):
            button = QPushButton(label)
            button.setProperty("quick", True)
            button.setCheckable(True)
            button.setChecked(not expression)
            button.clicked.connect(lambda checked=False, text=expression: self.set_filter(text))
            self.quick_controls.addWidget(button)
            self.quick_buttons[expression] = button
        self.quick_controls.addStretch()
        packet_layout.addLayout(self.quick_controls)
        flow_page = QWidget()
        flow_layout = QVBoxLayout(flow_page)
        flow_layout.setContentsMargins(0, 8, 0, 0)
        flow_layout.setSpacing(8)
        flow_controls = QHBoxLayout()
        self.process_filter = QLineEdit()
        self.process_filter.setClearButtonEnabled(True)
        self.process_filter.setPlaceholderText("输入 PID 或完整进程名，例如 python.exe")
        self.flow_button = QPushButton("追踪所选流")
        self.flow_button.setObjectName("primary")
        self.flow_filter_button = QPushButton("查看关联数据包")
        flow_controls.addWidget(heading("进程筛选"))
        flow_controls.addWidget(self.process_filter, 1)
        flow_controls.addWidget(self.flow_button)
        flow_controls.addWidget(self.flow_filter_button)
        flow_layout.addLayout(flow_controls)
        flow_layout.addWidget(heading("双击 TCP 流查看双向内容和时间线；PID 关联保留实际采样状态。", "hint"))
        self.flow_tree = QTreeWidget()
        self.flow_tree.setHeaderLabels(["流编号", "端点 A", "端点 B", "连接状态", "包数 A / B", "字节 A / B", "本机进程", "关联状态", "起止时间"])
        self.flow_tree.setRootIsDecorated(False)
        self.flow_tree.setAlternatingRowColors(True)
        self.flow_tree.setSelectionMode(QTreeWidget.SingleSelection)
        self.flow_tree.header().setStretchLastSection(False)
        for column, width in enumerate((60, 170, 170, 90, 90, 120, 180, 150, 170)):
            self.flow_tree.setColumnWidth(column, width)
        flow_layout.addWidget(self.flow_tree, 1)
        self.model = PacketModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setSortingEnabled(False)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setHorizontalScrollMode(QTableView.ScrollPerPixel)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(29)
        for column, width in enumerate((64, 128, 155, 155, 74, 74, 86, 110)):
            self.table.setColumnWidth(column, width)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.packet_flow_button = QPushButton("追踪此包的 TCP 流")
        self.packet_flow_button.setEnabled(False)
        self.packet_count = heading("暂无数据包", "hint")
        self.quick_controls.addWidget(self.packet_count)
        self.quick_controls.addWidget(self.packet_flow_button)
        self.details = QTreeWidget()
        self.details.setHeaderLabels(["协议/字段", "值"])
        self.details.setColumnWidth(0, 210)
        self.details.setAlternatingRowColors(True)
        self.details.setMinimumHeight(100)
        self.bytes_view = QPlainTextEdit()
        self.bytes_view.setReadOnly(True)
        self.bytes_view.setFont(QFont("Consolas", 10))
        self.bytes_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.bytes_view.setPlaceholderText("选择一个数据包，查看原始字节和 ASCII 内容")
        self.detail_split = QSplitter(Qt.Horizontal)
        for label, widget in (("协议详情", self.details), ("原始字节 · Hex / ASCII", self.bytes_view)):
            pane = QWidget()
            pane_layout = QVBoxLayout(pane)
            pane_layout.setContentsMargins(0, 0, 0, 0)
            pane_layout.setSpacing(5)
            pane_layout.addWidget(heading(label))
            pane_layout.addWidget(widget)
            self.detail_split.addWidget(pane)
        self.detail_split.setSizes([500, 650])
        self.detail_split.setChildrenCollapsible(False)
        self.main_split = QSplitter(Qt.Vertical)
        self.main_split.addWidget(self.table)
        self.main_split.addWidget(self.detail_split)
        self.main_split.setSizes([500, 230])
        self.main_split.setStretchFactor(0, 3)
        self.main_split.setStretchFactor(1, 2)
        self.main_split.setChildrenCollapsible(False)
        packet_layout.addWidget(self.main_split, 1)
        self.workspace_tabs.addTab(packet_page, "数据包")
        self.workspace_tabs.addTab(flow_page, "TCP 流")
        layout.addWidget(self.workspace_tabs, 1)
        metric_card, metric_layout = card()
        metric_row = QHBoxLayout()
        self.metrics = {}
        for key, label in (("captured", "已捕获"), ("displayed", "当前显示"), ("saved", "已保存"), ("bytes", "捕获数据"), ("rate", "平均速率")):
            block = QHBoxLayout()
            block.setSpacing(8)
            block.addWidget(heading(label, "hint"))
            value = heading("—", "metricValue")
            self.metrics[key] = value
            block.addWidget(value)
            metric_row.addLayout(block, 1)
        metric_layout.addLayout(metric_row)
        layout.addWidget(metric_card)
        self.status = heading("请选择网卡，或打开已有 PCAP 文件。", "hint")
        self.status.setWordWrap(True)
        self.status.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        layout.addWidget(self.status)
        self.refresh_button.clicked.connect(self.refresh_devices)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_display)
        self.open_button.clicked.connect(self.open_file)
        self.save_button.clicked.connect(self.export_file)
        self.apply_button.clicked.connect(self.apply_filter)
        self.display_filter.returnPressed.connect(self.apply_filter)
        self.packet_flow_button.clicked.connect(self.follow_selected_packet)
        self.flow_button.clicked.connect(self.follow_selected_flow)
        self.flow_filter_button.clicked.connect(self.filter_selected_flow)
        self.flow_tree.itemDoubleClicked.connect(self.follow_tree_flow)
        self.process_filter.textChanged.connect(self.refresh_flows)
        self.flow_tree.itemSelectionChanged.connect(self.update_flow_actions)
        self.table.selectionModel().selectionChanged.connect(self.show_packet)
        self.filter_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.filter_shortcut.activated.connect(self.focus_display_filter)
        self.timer = QTimer(self)
        self.timer.setInterval(100)
        self.timer.timeout.connect(self.refresh_packets)
        self.timer.start()
        self.refresh_devices()
        self.set_running(False)

    def show_error(self, title, error):
        QMessageBox.critical(self, title, str(error))

    def set_filter(self, expression):
        self.display_filter.setText(expression)
        self.apply_filter()

    def focus_display_filter(self):
        self.workspace_tabs.setCurrentIndex(0)
        self.display_filter.setFocus()
        self.display_filter.selectAll()

    def update_packet_count(self):
        count = len(self.model.rows)
        self.workspace_tabs.setTabText(0, f"数据包  {count:,}")
        self.metrics["displayed"].setText(f"{count:,}")
        if self.history:
            self.packet_count.setText(f"{count:,} / {len(self.history):,} 包")
        else:
            self.packet_count.setText("暂无数据包")

    def apply_filter(self):
        try:
            expression = compile_filter(self.display_filter.text())
            self.filter_function = expression
            self.model.replace([packet for packet in self.history if expression(packet)])
            self.display_filter.setProperty("invalid", False)
            self.filter_feedback.hide()
            for text, button in self.quick_buttons.items():
                button.setChecked(text == self.display_filter.text().strip())
            self.update_packet_count()
        except FilterError as error:
            self.display_filter.setProperty("invalid", True)
            self.filter_feedback.setText(str(error))
            self.filter_feedback.show()
        self.display_filter.style().unpolish(self.display_filter)
        self.display_filter.style().polish(self.display_filter)

    def refresh_devices(self):
        self.adapters.clear()
        try:
            for device in Npcap().devices():
                label = f"{device.description}  ·  {', '.join(device.addresses) or '地址未提供'}"
                self.adapters.addItem(label, device.name)
                self.adapters.setItemData(self.adapters.count() - 1, f"{label}\n{device.name}", Qt.ToolTipRole)
        except (CaptureError, OSError) as error:
            self.status.setText(str(error))

    def set_running(self, running):
        exporting = self.export_thread is not None and self.export_thread.is_alive()
        for widget in (self.start_button, self.refresh_button, self.adapters, self.bpf, self.snaplen,
                       self.buffer_mb, self.timeout_ms, self.promiscuous, self.open_button):
            widget.setEnabled(not running and not exporting)
        self.stop_button.setEnabled(running)
        self.save_button.setEnabled(not running and not exporting and self.engine is not None and self.engine.stats.saved > 0)
        phase = "running" if running else "idle"
        offline = self.engine is not None and self.engine.source is not None
        self.state_badge.setText(("正在读取" if offline else "正在抓包") if running else
                                ("已载入" if offline else "已停止") if self.engine else "未开始")
        if self.engine and self.engine.error:
            phase = "error"
            self.state_badge.setText("操作失败")
        if self.state_badge.property("phase") != phase:
            self.state_badge.setProperty("phase", phase)
            self.state_badge.style().unpolish(self.state_badge)
            self.state_badge.style().polish(self.state_badge)
        self.update_flow_actions()

    def make_engine(self, config=None, source=None):
        self.analyzer = StreamManager()
        if self.tracker:
            self.tracker.stop()
            self.tracker = None
        if config:
            self.tracker = ProcessTracker()
            self.tracker.start()
        return CaptureEngine(ROOT / "output" / "sessions", config=config, source=source,
                             parser=self.parser, analyzer=self.analyzer, process_tracker=self.tracker)

    def start_capture(self):
        try:
            config = CaptureConfig(self.adapters.currentData() or "", self.bpf.text(), self.snaplen.value(),
                                   self.promiscuous.isChecked(), self.timeout_ms.value(), self.buffer_mb.value())
            self.begin(config=config)
        except (ValueError, OSError, RuntimeError) as error:
            self.show_error("无法开始", error)

    def begin(self, config=None, source=None):
        self.clear_display()
        self.display_floor = 0
        self.reported_error = ""
        self.export_message = ""
        self.engine = self.make_engine(config, source)
        self.engine.start()
        self.session_label.setText(self.session_label.fontMetrics().elidedText(Path(source).name, Qt.ElideMiddle, 180) if source else "实时捕获")
        self.session_label.setToolTip(str(source or self.engine.directory))
        self.set_running(True)

    def update_flow_actions(self):
        available = bool(self.flow_tree.selectedItems())
        self.flow_button.setEnabled(available)
        self.flow_filter_button.setEnabled(available)

    def follow_selected_flow(self):
        selected = self.flow_tree.selectedItems()
        if selected:
            self.show_flow(selected[0].data(0, Qt.UserRole))

    def follow_selected_packet(self):
        packet = self.selected_packet()
        if packet and packet.stream_id is not None:
            self.show_flow(packet.stream_id)

    def follow_tree_flow(self, item, column):
        self.show_flow(item.data(0, Qt.UserRole))

    def show_flow(self, identifier):
        flow = self.analyzer.get(identifier)
        if flow is None:
            self.show_error("流不可用", "该流已离开内存保留窗口，请重新打开完整会话")
            return
        dialog = FlowDialog(flow, self)
        dialog.exec()

    def filter_selected_flow(self):
        items = self.flow_tree.selectedItems()
        packet = self.selected_packet()
        identifier = items[0].data(0, Qt.UserRole) if items else (packet.stream_id if packet else None)
        if identifier is not None:
            self.set_filter(f"tcp.stream == {identifier}")
            self.workspace_tabs.setCurrentIndex(0)

    def refresh_flows(self):
        selected = self.flow_tree.selectedItems()
        selected_id = selected[0].data(0, Qt.UserRole) if selected else None
        self.flow_tree.clear()
        query = self.process_filter.text().strip().lower()
        flows = self.analyzer.snapshot()
        for flow in flows:
            owners = flow["owners"]
            if query and not any(query == str(owner["pid"]) or query == owner["name"].lower() for owner in owners):
                continue
            names = sorted({f"{owner['pid']} {owner['name']}" for owner in owners})
            times = [time.strftime("%H:%M:%S", time.localtime(flow[key] / 1e9)) for key in ("started", "ended")]
            associations = " / ".join(ASSOCIATIONS.get(value, value) for value in flow["association_statuses"])
            item = QTreeWidgetItem([str(flow["id"]), endpoint(flow["endpoints"][0]), endpoint(flow["endpoints"][1]),
                                    STATES.get(flow["state"], flow["state"]), " / ".join(map(str, flow["packets"])),
                                    " / ".join(size_text(value) for value in flow["bytes"]), "; ".join(names) or "未知",
                                    associations, " – ".join(times)])
            item.setData(0, Qt.UserRole, flow["id"])
            item.setToolTip(7, "部分包可能在采样时无法匹配。" + "\n" + ", ".join(flow["association_statuses"]))
            item.setForeground(7, QColor("#167047" if owners else "#687991"))
            self.flow_tree.addTopLevelItem(item)
            if flow["id"] == selected_id:
                item.setSelected(True)
        self.workspace_tabs.setTabText(1, f"TCP 流  {self.flow_tree.topLevelItemCount()} / {len(flows)}")
        self.update_flow_actions()

    def stop_capture(self):
        if self.engine:
            self.engine.stop()
            self.stop_button.setEnabled(False)

    def clear_display(self):
        self.display_floor = self.engine.stats.captured + 1 if self.engine else 0
        self.history.clear()
        self.history_bytes = 0
        self.evicted = 0
        self.model.replace([])
        self.details.clear()
        self.bytes_view.clear()
        self.packet_flow_button.setEnabled(False)
        self.update_packet_count()

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "打开标准 PCAP", str(ROOT / "output"), "PCAP (*.pcap *.cap)")
        if path:
            self.begin(source=path)

    def export_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "导出完整会话及进程信息", str(ROOT / "output" / "capture.pcap"), "PCAP (*.pcap)")
        if path:
            self.begin_export(path)

    def begin_export(self, path):
        if not self.engine or not self.engine.finished.is_set():
            raise RuntimeError("导出前需要停止采集并完成磁盘写入")
        if self.export_thread and self.export_thread.is_alive():
            raise RuntimeError("已有导出任务正在运行")
        directory = self.engine.directory

        def write():
            try:
                export_session(directory, path)
                self.export_results.put((str(path), None))
            except Exception as error:
                logging.exception("导出失败")
                self.export_results.put((str(path), error))

        self.export_message = "正在后台导出完整会话"
        self.export_thread = threading.Thread(target=write, name="lab-export", daemon=False)
        self.export_thread.start()
        self.set_running(False)

    def refresh_packets(self):
        if not self.export_results.empty():
            path, error = self.export_results.get_nowait()
            self.export_message = f"已导出：{path} 和配套 .labproc.json" if error is None else "导出失败"
            if error:
                self.show_error("导出失败", error)
        if not self.engine:
            return
        batch = []
        deadline = time.monotonic() + 0.025
        while len(batch) < 300 and time.monotonic() < deadline:
            try:
                packet = self.engine.gui_queue.get_nowait()
                if packet.raw.number >= self.display_floor:
                    batch.append(packet)
            except queue.Empty:
                break
        if batch:
            self.history.extend(batch)
            self.history_bytes += sum(p.raw.caplen for p in batch)
            while len(self.history) > 5000 or self.history_bytes > 32 * 1024 * 1024:
                removed = self.history.pop(0)
                self.history_bytes -= removed.raw.caplen
                self.evicted += 1
            selected = self.selected_packet()
            self.model.replace([packet for packet in self.history if self.filter_function(packet)])
            if selected:
                for index, packet in enumerate(self.model.rows):
                    if packet.raw.number == selected.raw.number:
                        self.table.selectRow(index)
                        break
        stats = self.engine.snapshot()
        driver = stats["driver_drops"] if stats["driver_drops"] is not None else "未知"
        interface = stats["interface_drops"] if stats["interface_drops"] is not None else "未知"
        self.metrics["captured"].setText(f"{stats['captured']:,}")
        self.metrics["saved"].setText(f"{stats['saved']:,}")
        self.metrics["bytes"].setText(size_text(stats["bytes"]))
        self.metrics["rate"].setText(f"{stats['packets_per_second']:.1f} 包/s")
        self.metrics["rate"].setToolTip(f"会话平均速率：{size_text(stats['bytes_per_second'])}/s")
        self.update_packet_count()
        self.status.setText(f"驱动丢包 {driver} · 接口丢包 {interface} · 采集队列丢弃 {stats['capture_queue_drops']} · "
                            f"GUI 队列丢弃 {stats['gui_queue_drops']} · 窗口淘汰 {self.evicted}" +
                            (f"\n{self.engine.error}" if self.engine.error else "") +
                            (f"\n{self.export_message}" if self.export_message else ""))
        if self.engine.finished.is_set():
            self.set_running(False)
        if not hasattr(self, "last_flow_refresh") or time.monotonic() - self.last_flow_refresh > 0.5:
            self.refresh_flows()
            self.last_flow_refresh = time.monotonic()
        if self.engine.error and self.reported_error != self.engine.error:
            self.reported_error = self.engine.error
            self.show_error("操作已停止", self.engine.error)

    def selected_packet(self):
        rows = self.table.selectionModel().selectedRows()
        return self.model.rows[rows[0].row()] if rows and rows[0].row() < len(self.model.rows) else None

    def show_packet(self):
        packet = self.selected_packet()
        self.packet_flow_button.setEnabled(packet is not None and packet.stream_id is not None)
        if not packet:
            return
        self.details.clear()
        for name, values in packet.layers.items():
            item = QTreeWidgetItem([name, ""])
            self.details.addTopLevelItem(item)
            self.add_detail_values(item, values)
        item = QTreeWidgetItem(["进程关联", ASSOCIATIONS.get(packet.process["status"], packet.process["status"])])
        self.details.addTopLevelItem(item)
        self.add_detail_values(item, packet.process)
        for error in packet.errors:
            self.details.addTopLevelItem(QTreeWidgetItem(["解析提示", error]))
        self.details.expandToDepth(0)
        self.bytes_view.setPlainText(hex_view(packet.raw.data))

    def add_detail_values(self, parent, values):
        entries = values.items() if isinstance(values, dict) else enumerate(values, 1)
        for key, value in entries:
            nested = isinstance(value, (dict, list, tuple))
            item = QTreeWidgetItem(parent, [str(key), f"{len(value)} 项" if nested else str(value)])
            if nested:
                self.add_detail_values(item, value)

    def closeEvent(self, event):
        if self.export_thread and self.export_thread.is_alive():
            event.ignore()
            QTimer.singleShot(100, self.close)
            return
        if self.engine and any(thread.is_alive() for thread in self.engine.threads):
            self.engine.stop()
            event.ignore()
            QTimer.singleShot(100, self.close)
            return
        if self.tracker:
            self.tracker.stop()
        event.accept()


def main():
    output = ROOT / "output"
    output.mkdir(exist_ok=True)
    logging.basicConfig(filename=output / "application.log", level=logging.INFO, encoding="utf-8",
                        format="%(asctime)s %(levelname)s %(message)s")
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
