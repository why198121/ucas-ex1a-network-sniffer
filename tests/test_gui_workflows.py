import json
import time
from pathlib import Path

import pytest
from PySide6.QtCore import QPoint

from labsniffer.flow_gui import FlowDialog
from labsniffer.gui import MainWindow
from labsniffer.storage import PcapFile, load_metadata


@pytest.mark.gui
def test_real_capture_navigation_and_responsive_layout(evidence_dir, qt_app):
    record_path = evidence_dir / "tcp_pid_18080.json"
    if not record_path.exists():
        pytest.skip("需要实际 TCP/PID 捕获作为 GUI 文件重开检查的输入")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    capture = Path(record["pcap"])
    metadata = load_metadata(capture)
    window = MainWindow()
    window.show()
    dialog = None
    measurements = []
    try:
        window.begin(source=capture)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            qt_app.processEvents()
            if window.engine.finished.is_set() and window.engine.gui_queue.empty():
                break
            time.sleep(0.005)
        window.engine.wait(2)
        window.refresh_packets()
        assert not window.engine.error, window.engine.error
        assert window.model.rowCount() == metadata["packet_count"]
        for width, height in ((1024, 720), (1280, 800), (1440, 900)):
            window.resize(width, height)
            window.workspace_tabs.setCurrentIndex(0)
            qt_app.processEvents()
            assert window.width() == width and window.height() == height
            assert window.table.viewport().height() >= 180
            for control in (window.start_button, window.stop_button, window.open_button, window.save_button,
                            window.adapters, window.display_filter, window.apply_button, window.packet_flow_button):
                position = control.mapTo(window, QPoint(0, 0))
                assert 0 <= position.x() and 0 <= position.y()
                assert position.x() + control.width() <= window.width()
                assert position.y() + control.height() <= window.height()
            packet_height = window.table.viewport().height()
            window.workspace_tabs.setCurrentIndex(1)
            qt_app.processEvents()
            assert window.flow_tree.viewport().height() >= 250
            measurements.append({"window": [width, height], "packet_viewport_height": packet_height,
                                 "flow_viewport_height": window.flow_tree.viewport().height()})
        window.parameter_button.click()
        assert window.parameter_panel.isVisible() and window.bpf.isVisible()
        window.parameter_button.click()
        window.process_filter.setText(str(record["pid"]))
        assert window.flow_tree.topLevelItemCount() == 3
        window.flow_tree.topLevelItem(0).setSelected(True)
        identifier = window.flow_tree.topLevelItem(0).text(0)
        window.filter_selected_flow()
        assert window.workspace_tabs.currentIndex() == 0
        expected = {item["original_number"] for item in metadata["packets"] if item["stream_id"] == int(identifier)}
        assert {packet.raw.number for packet in window.model.rows} == expected
        previous = list(window.model.rows)
        window.set_filter("tcp and")
        assert window.filter_feedback.isVisible()
        assert window.model.rows == previous
        window.set_filter("")
        assert not window.filter_feedback.isVisible()
        assert window.model.rowCount() == metadata["packet_count"]
        flow = window.analyzer.get(int(identifier))
        dialog = FlowDialog(flow, window)
        dialog.show()
        qt_app.processEvents()
        assert "GET /split/" in dialog.editors[0].toPlainText()
        assert "HTTP/1.1 200 OK" in dialog.editors[1].toPlainText()
        dialog.content_format.setCurrentIndex(1)
        assert "47 45 54" in dialog.editors[0].toPlainText()
        assert dialog.timeline.topLevelItemCount() == len(flow["events"])
        assert dialog.http_tree.topLevelItemCount() == 2
        assert any(str(record["pid"]) in dialog.process_tree.topLevelItem(index).text(0)
                   for index in range(dialog.process_tree.topLevelItemCount()))
        window.clear_display()
        assert window.model.rowCount() == 0
        assert len(list(PcapFile.read(capture))) == metadata["packet_count"]
    finally:
        if dialog:
            dialog.close()
        window.close()
        qt_app.processEvents()
    (evidence_dir / "gui_navigation.json").write_text(json.dumps({"status": "PASS", "pcap": str(capture),
        "measurements": measurements, "verified": ["按 PID 查看多个流", "从流筛选包", "错误过滤提示", "文本与十六进制切换",
            "HTTP 消息树", "进程采样信息", "连接时间线", "清空显示保留原始文件"]}, ensure_ascii=False, indent=2), encoding="utf-8")
