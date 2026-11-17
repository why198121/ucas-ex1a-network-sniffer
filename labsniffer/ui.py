from PySide6.QtGui import QFont
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout


PROTOCOL_COLORS = {
    "HTTP": ("#E6F4EC", "#167047"), "TCP": ("#E8EFFD", "#285CB1"),
    "UDP": ("#FFF1DF", "#975E0B"), "DNS": ("#F0EAFE", "#7045A1"),
    "TLS": ("#ECEBFA", "#5753A5"), "LABDEMO": ("#DEF4F2", "#08766E"),
    "ICMP": ("#EEF1F5", "#4C5E78"), "ICMPv6": ("#EEF1F5", "#4C5E78"),
    "ARP": ("#FAEDE5", "#925233"),
}
STATES = {"MIDSTREAM": "中途观察", "SYN_SENT": "请求连接", "SYN_ACK": "握手响应", "ESTABLISHED": "已建立",
          "PARTIAL_HANDSHAKE": "握手不完整", "HALF_CLOSED": "单向关闭", "CLOSED": "已关闭", "RESET": "已重置"}
ASSOCIATIONS = {"observed": "已观察", "unknown": "未匹配", "sampling_error": "采样失败", "not_tcp": "不适用",
                "process_exited": "进程已退出", "permission_denied": "权限不足", "uncertain_reuse": "身份复用不确定",
                "uncertain_stale": "连接已消失", "uncertain_scope": "接口范围不确定"}

STYLE = """
QMainWindow, QDialog { background: #F3F6FA; color: #25344A; }
QWidget { color: #25344A; }
QFrame#card { background: #FFFFFF; border: 1px solid #DDE4ED; border-radius: 9px; }
QLabel#title { font-size: 23px; font-weight: 650; color: #182C49; }
QLabel#hint { color: #687991; font-size: 12px; }
QLabel#sectionTitle { color: #354A66; font-weight: 600; padding: 1px 0px; }
QLabel#metricValue { color: #1E3C61; font-size: 19px; font-weight: 600; }
QLabel#badge { padding: 5px 12px; border-radius: 12px; background: #E6ECF4; color: #52657F; }
QLabel#badge[phase="running"] { background: #DDF3E9; color: #167047; }
QLabel#badge[phase="error"] { background: #FCE8E6; color: #AF4038; }
QLabel#feedback { color: #AF4038; font-size: 12px; }
QPushButton, QToolButton { background: #FFFFFF; border: 1px solid #CBD6E4; border-radius: 6px; padding: 6px 12px; min-height: 19px; }
QPushButton:hover, QToolButton:hover { background: #F0F5FC; border-color: #8FAED6; }
QPushButton:pressed, QToolButton:pressed { background: #DFEAF9; }
QPushButton:disabled, QToolButton:disabled { color: #9CAABD; background: #F6F8FB; border-color: #E2E8F0; }
QPushButton#primary { color: #FFFFFF; background: #2866B8; border-color: #2866B8; font-weight: 600; }
QPushButton#primary:hover { background: #21599F; }
QPushButton#primary:disabled { color: #EDF2FA; background: #9CB8DA; border-color: #9CB8DA; }
QPushButton#stop { color: #AD463E; background: #FFF9F8; border-color: #EACAC5; }
QPushButton#stop:disabled { color: #B8ACAC; border-color: #E7E1E1; }
QPushButton[quick="true"] { padding: 3px 12px; min-height: 18px; border-color: #E1E7EF; }
QPushButton[quick="true"]:checked { color: #225A9D; background: #E8F0FD; border-color: #A8C3E7; font-weight: 600; }
QLineEdit, QComboBox, QSpinBox { background: #FFFFFF; border: 1px solid #CBD6E4; border-radius: 5px; padding: 5px 8px; min-height: 21px; selection-background-color: #D6E6FC; selection-color: #17385F; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #4680CB; }
QLineEdit[invalid="true"] { border-color: #D77C72; background: #FFF8F7; }
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled { color: #8493A7; background: #F5F7FA; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView { background: white; selection-background-color: #E8F0FD; selection-color: #25344A; }
QTableView, QTreeWidget, QPlainTextEdit { background: #FFFFFF; alternate-background-color: #F8FAFD; border: 1px solid #E1E7EF; border-radius: 6px; gridline-color: #EEF2F7; selection-background-color: #DBE9FB; selection-color: #193C69; }
QTableView::item { padding: 3px 7px; border: none; }
QTreeWidget::item { padding: 4px 3px; }
QHeaderView::section { background: #F4F7FB; color: #536780; font-weight: 600; border: none; border-bottom: 1px solid #DEE6F0; padding: 7px; }
QTabWidget::pane { border: none; background: transparent; }
QTabBar::tab { background: transparent; color: #687991; padding: 9px 18px; border-bottom: 3px solid transparent; }
QTabBar::tab:selected { color: #245EAA; border-bottom: 3px solid #3679CD; font-weight: 600; }
QTabBar::tab:hover { background: #EBF1FA; }
QSplitter::handle { background: #E5EBF3; }
QSplitter::handle:horizontal { width: 5px; margin: 5px 0px; }
QSplitter::handle:vertical { height: 5px; margin: 0px 5px; }
QToolTip { background: #FFFFFF; color: #25344A; border: 1px solid #BACBE0; padding: 6px; }
"""


def apply_theme(widget):
    widget.setFont(QFont("Microsoft YaHei UI", 10))
    widget.setStyleSheet(STYLE)


def card():
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(12, 10, 12, 10)
    layout.setSpacing(8)
    return frame, layout


def heading(text, style="sectionTitle"):
    label = QLabel(text)
    label.setObjectName(style)
    return label


def endpoint(value):
    address, port = value
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def size_text(value):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1024
