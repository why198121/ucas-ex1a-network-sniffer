import json
import logging
import queue
import sys
import time
from pathlib import Path

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel,
                               QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
                               QSpinBox, QSplitter, QTableView, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from .capture import CaptureEngine
from .filters import FilterError, compile_filter
from .npcap import CaptureConfig, CaptureError, Npcap
from .protocols import parse_packet
from .storage import export_session


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
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        packet = self.rows[index.row()]
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
        self.resize(1440, 900)
        self.engine = None
        self.history = []
        self.history_bytes = 0
        self.evicted = 0
        self.reported_error = ""
        self.filter_function = lambda packet: True
        self.parser = parse_packet
        self.analyzer = None
        self.tracker = None
        central = QWidget()
        layout = QVBoxLayout(central)
        self.setCentralWidget(central)
        controls = QHBoxLayout()
        self.adapters = QComboBox()
        self.adapters.setMinimumWidth(440)
        controls.addWidget(self.adapters, 1)
        self.refresh_button = QPushButton("刷新网卡")
        self.start_button = QPushButton("开始新会话")
        self.stop_button = QPushButton("停止")
        self.clear_button = QPushButton("清空显示")
        self.open_button = QPushButton("打开 PCAP")
        self.save_button = QPushButton("导出 PCAP + PID")
        for button in (self.refresh_button, self.start_button, self.stop_button, self.clear_button, self.open_button, self.save_button):
            controls.addWidget(button)
        layout.addLayout(controls)
        settings = QHBoxLayout()
        self.bpf = QLineEdit()
        self.bpf.setPlaceholderText("抓包过滤 BPF，例如 tcp or udp port 53；开始前设置")
        settings.addWidget(self.bpf, 1)
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
        layout.addLayout(settings)
        display_controls = QHBoxLayout()
        self.display_filter = QLineEdit()
        self.display_filter.setPlaceholderText('显示过滤，例如 tcp and port == 8080；只影响内存窗口')
        self.apply_button = QPushButton("应用显示过滤")
        display_controls.addWidget(self.display_filter, 1)
        display_controls.addWidget(self.apply_button)
        layout.addLayout(display_controls)
        self.quick_controls = QHBoxLayout()
        for label, expression in (("全部", ""), ("HTTP", "http"), ("TCP", "tcp"), ("UDP", "udp"),
                                  ("IPv4", "ipv4"), ("IPv6", "ipv6"), ("ICMP", "icmp or icmpv6"), ("DNS", "dns")):
            button = QPushButton(label)
            button.clicked.connect(lambda checked=False, text=expression: self.set_filter(text))
            self.quick_controls.addWidget(button)
        layout.addLayout(self.quick_controls)
        self.model = PacketModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setSortingEnabled(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.details = QTreeWidget()
        self.details.setHeaderLabels(["协议/字段", "值"])
        self.details.setColumnWidth(0, 260)
        self.bytes_view = QPlainTextEdit()
        self.bytes_view.setReadOnly(True)
        self.bytes_view.setFont(QFont("Consolas", 10))
        detail_split = QSplitter(Qt.Horizontal)
        detail_split.addWidget(self.details)
        detail_split.addWidget(self.bytes_view)
        self.main_split = QSplitter(Qt.Vertical)
        self.main_split.addWidget(self.table)
        self.main_split.addWidget(detail_split)
        self.main_split.setSizes([450, 300])
        layout.addWidget(self.main_split, 1)
        self.status = QLabel("请选择网卡；完整会话保存在 output/sessions")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.refresh_button.clicked.connect(self.refresh_devices)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_display)
        self.open_button.clicked.connect(self.open_file)
        self.save_button.clicked.connect(self.export_file)
        self.apply_button.clicked.connect(self.apply_filter)
        self.display_filter.returnPressed.connect(self.apply_filter)
        self.table.selectionModel().selectionChanged.connect(self.show_packet)
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

    def apply_filter(self):
        try:
            expression = compile_filter(self.display_filter.text())
            self.filter_function = expression
            self.model.replace([packet for packet in self.history if expression(packet)])
        except FilterError as error:
            self.show_error("显示过滤错误", error)

    def refresh_devices(self):
        self.adapters.clear()
        try:
            for device in Npcap().devices():
                label = f"{device.description} | {', '.join(device.addresses) or '地址未提供'} | {device.name}"
                self.adapters.addItem(label, device.name)
                self.adapters.setItemData(self.adapters.count() - 1, label, Qt.ToolTipRole)
        except (CaptureError, OSError) as error:
            self.status.setText(str(error))

    def set_running(self, running):
        for widget in (self.start_button, self.refresh_button, self.adapters, self.bpf, self.snaplen,
                       self.buffer_mb, self.timeout_ms, self.promiscuous, self.open_button):
            widget.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.save_button.setEnabled(not running and self.engine is not None and self.engine.stats.saved > 0)

    def make_engine(self, config=None, source=None):
        return CaptureEngine(ROOT / "output" / "sessions", config=config, source=source,
                             parser=self.parser, analyzer=self.analyzer, process_tracker=self.tracker)

    def start_capture(self):
        try:
            config = CaptureConfig(self.adapters.currentData() or "", self.bpf.text(), self.snaplen.value(),
                                   self.promiscuous.isChecked(), self.timeout_ms.value(), self.buffer_mb.value())
            self.begin(config=config)
        except (ValueError, OSError) as error:
            self.show_error("无法开始", error)

    def begin(self, config=None, source=None):
        self.clear_display()
        self.reported_error = ""
        self.engine = self.make_engine(config, source)
        self.engine.start()
        self.set_running(True)

    def stop_capture(self):
        if self.engine:
            self.engine.stop()
            self.stop_button.setEnabled(False)

    def clear_display(self):
        self.history.clear()
        self.history_bytes = 0
        self.evicted = 0
        self.model.replace([])
        self.details.clear()
        self.bytes_view.clear()

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "打开标准 PCAP", str(ROOT / "output"), "PCAP (*.pcap *.cap)")
        if path:
            self.begin(source=path)

    def export_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "导出完整会话及进程信息", str(ROOT / "output" / "capture.pcap"), "PCAP (*.pcap)")
        if path:
            try:
                export_session(self.engine.directory, path)
                self.status.setText(f"已导出：{path} 和配套 .labproc.json")
            except (ValueError, OSError) as error:
                self.show_error("导出失败", error)

    def refresh_packets(self):
        if not self.engine:
            return
        batch = []
        deadline = time.monotonic() + 0.025
        while len(batch) < 300 and time.monotonic() < deadline:
            try:
                batch.append(self.engine.gui_queue.get_nowait())
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
        self.status.setText(f"捕获 {stats['captured']} | 解析 {stats['parsed']} | 显示 {len(self.model.rows)} | 已保存 {stats['saved']} | "
                            f"捕获字节 {stats['bytes']} | 平均 {stats['packets_per_second']:.1f} 包/s · {stats['bytes_per_second']:.1f} B/s | "
                            f"驱动丢包 {driver} · 接口丢包 {interface} | 采集队列丢弃 {stats['capture_queue_drops']} · "
                            f"GUI 队列丢弃 {stats['gui_queue_drops']} · 窗口淘汰 {self.evicted} | "
                            f"{'已停止' if self.engine.finished.is_set() else '运行中'} {self.engine.error}")
        if self.engine.finished.is_set():
            self.set_running(False)
        if self.engine.error and self.reported_error != self.engine.error:
            self.reported_error = self.engine.error
            self.show_error("操作已停止", self.engine.error)

    def selected_packet(self):
        rows = self.table.selectionModel().selectedRows()
        return self.model.rows[rows[0].row()] if rows else None

    def show_packet(self):
        packet = self.selected_packet()
        if not packet:
            return
        self.details.clear()
        for name, values in packet.layers.items():
            item = QTreeWidgetItem([name, ""])
            self.details.addTopLevelItem(item)
            for key, value in values.items():
                QTreeWidgetItem(item, [key, str(value)])
        item = QTreeWidgetItem(["进程关联", packet.process["status"]])
        self.details.addTopLevelItem(item)
        QTreeWidgetItem(item, ["证据", json.dumps(packet.process, ensure_ascii=False)])
        for error in packet.errors:
            self.details.addTopLevelItem(QTreeWidgetItem(["解析提示", error]))
        self.details.expandAll()
        self.bytes_view.setPlainText(hex_view(packet.raw.data))

    def closeEvent(self, event):
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
