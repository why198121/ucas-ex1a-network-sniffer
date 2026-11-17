import argparse
import ctypes
from ctypes import wintypes
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import traceback

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from labsniffer.cli import wireshark_arguments
from labsniffer.flow_gui import FlowDialog
from labsniffer.gui import MainWindow
from labsniffer.storage import load_metadata, PcapFile


USER = ctypes.WinDLL('user32', use_last_error=True)
USER.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
USER.GetClientRect.restype = wintypes.BOOL
USER.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
USER.GetWindowRect.restype = wintypes.BOOL
USER.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
USER.ClientToScreen.restype = wintypes.BOOL
USER.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.UINT]
USER.SetWindowPos.restype = wintypes.BOOL
USER.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
USER.ShowWindow.restype = wintypes.BOOL
USER.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
USER.GetWindowThreadProcessId.restype = wintypes.DWORD
USER.IsWindowVisible.argtypes = [wintypes.HWND]
USER.IsWindowVisible.restype = wintypes.BOOL
USER.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
USER.GetWindowTextW.restype = ctypes.c_int
ENUM = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
USER.EnumWindows.argtypes = [ENUM, wintypes.LPARAM]
USER.EnumWindows.restype = wintypes.BOOL


def client_rectangle(handle):
    rectangle, point = wintypes.RECT(), wintypes.POINT()
    if not USER.GetClientRect(handle, ctypes.byref(rectangle)) or not USER.ClientToScreen(handle, ctypes.byref(point)):
        raise ctypes.WinError(ctypes.get_last_error())
    return [point.x, point.y, rectangle.right, rectangle.bottom]


def windows_for(pid, include_hidden=False):
    result = []
    @ENUM
    def visit(handle, extra):
        owner = wintypes.DWORD()
        USER.GetWindowThreadProcessId(handle, ctypes.byref(owner))
        if owner.value == pid and (include_hidden or USER.IsWindowVisible(handle)):
            name = ctypes.create_unicode_buffer(256)
            USER.GetWindowTextW(handle, name, len(name))
            result.append((int(handle), name.value))
        return True
    if not USER.EnumWindows(visit, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    return result


def position_window(handle, target):
    USER.ShowWindow(handle, 9)
    outer = wintypes.RECT()
    if not USER.GetWindowRect(handle, ctypes.byref(outer)):
        raise ctypes.WinError(ctypes.get_last_error())
    x, y, width, height = client_rectangle(handle)
    tx, ty, tw, th = target
    if not USER.SetWindowPos(handle, -1, tx - (x - outer.left), ty - (y - outer.top),
                             tw + outer.right - outer.left - width, th + outer.bottom - outer.top - height, 64):
        raise ctypes.WinError(ctypes.get_last_error())
    assert client_rectangle(handle) == target, (client_rectangle(handle), target)


class Demonstration:
    def __init__(self, app, args):
        self.app, self.args = app, args
        self.directory = ROOT / 'output/video' / time.strftime('%Y%m%d_%H%M%S')
        self.directory.mkdir(parents=True)
        (ROOT / '.work/video-current.json').write_text(json.dumps({'directory': str(self.directory), 'pid': os.getpid()}, ensure_ascii=False), encoding='utf-8')
        logging.basicConfig(filename=self.directory / 'controller.log', level=logging.INFO, encoding='utf-8')
        self.events, self.processes, self.logs = [], {}, []
        self.scale = 0.3 if args.rehearse else 1.0
        self.recording, self.dialog, self.traffic = None, None, None
        self.window = MainWindow()
        self.window.setWindowFlag(Qt.WindowStaysOnTopHint, True)
        self.window.setGeometry(80, 60, 1280, 680)
        self.window.show()
        for index in range(self.window.adapters.count()):
            if 'Loopback' in self.window.adapters.itemData(index):
                self.window.adapters.setCurrentIndex(index)
                break
        else:
            raise RuntimeError('未找到真实 Npcap loopback 接口')
        self.window.bpf.setText('tcp port 18080 or udp port 45990 or udp port 53 or icmp or icmp6')
        self.export_path = self.directory / 'demo_capture.pcap'
        self.started = None
        self.cursor = 0
        self.steps = [
            (3, '网卡选择', self.window.adapters.showPopup), (8, '确认网卡', self.window.adapters.hidePopup),
            (10, '捕获参数与 BPF', self.window.parameter_button.click),
            (18, '开始实时抓包', self.window.start_button.click), (21, '产生真实流量', self.start_traffic),
            (25, '关闭参数面板', self.window.parameter_button.click), (30, '实时包列表', lambda: self.select_packet()),
            (38, '停止捕获', self.window.stop_button.click), (43, '核实实际捕获', self.check_capture),
            (50, 'HTTP 请求', lambda: self.filter_packet('http', lambda p: 'http.method' in p.fields, 'HTTP')),
            (62, 'HTTP 响应', lambda: self.filter_packet('http', lambda p: 'http.status' in p.fields, 'HTTP')),
            (72, 'UDP 教学协议', lambda: self.filter_packet('udp', lambda p: p.protocol == 'LABDEMO', 'LABDEMO')),
            (82, '异常 UDP 长度', lambda: self.filter_packet('udp', lambda p: 'invalid_length' in p.summary, 'LABDEMO')),
            (90, 'DNS 查询与答案', lambda: self.filter_packet('dns', lambda p: p.layers.get('DNS', {}).get('records'), 'DNS')),
            (98, 'IPv4 过滤', lambda: self.filter_packet('ipv4')), (101, 'IPv6 过滤', lambda: self.filter_packet('ipv6')),
            (105, 'ICMP 与 ICMPv6', lambda: self.filter_packet('icmp or icmpv6')),
            (111, '逻辑组合过滤', lambda: self.filter_packet('tcp and (port == 18080) and addr == "127.0.0.1"')),
            (119, 'TCP 会话列表', self.show_flows), (130, 'PID 筛选三条流', self.filter_process),
            (140, 'TCP 请求方向重组', self.show_flow), (151, 'TCP 响应方向重组', lambda: self.dialog.tabs.setCurrentIndex(1)),
            (157, 'TCP 十六进制内容', lambda: self.dialog.content_format.setCurrentIndex(1)),
            (164, '连接事件时间线', lambda: self.dialog.tabs.setCurrentIndex(2)),
            (176, '结构化 HTTP 消息', lambda: self.dialog.tabs.setCurrentIndex(3)),
            (189, '进程生命周期与采样', lambda: self.dialog.tabs.setCurrentIndex(4)),
            (201, '返回主窗口', self.close_flow), (204, '导出 PCAP 与 PID', lambda: self.window.begin_export(self.export_path)),
            (211, '校验导出配对', self.check_export), (214, '清空显示', self.window.clear_button.click),
            (215, '重新开始独立会话', self.window.start_button.click), (217, '空闲捕获停止', self.window.stop_button.click),
            (218, '重新读取 PCAP', lambda: self.window.begin(source=self.export_path)),
            (223, '恢复历史包与 PID', self.check_reopen), (225, '准备 Wireshark 窗口', self.launch_wireshark),
            (231, 'Wireshark LABDEMO', lambda: self.front('LABDEMO')),
            (235, '展开协议字段', lambda: self.ui('LABDEMO', 'Expand', 'UCAS teaching UDP protocol')),
            (242, '按请求编号筛选', lambda: self.ui('LABDEMO', 'Filter', 'labdemo.request_id == 1001')),
            (251, '恢复全部教学协议包', lambda: self.ui('LABDEMO', 'Filter', 'labdemo')),
            (254, 'Wireshark PID 字段', lambda: self.front('PID')),
            (258, '展开进程关联', lambda: self.ui('PID', 'Expand', 'UCAS local process observations')),
            (263, '查看 PID 与进程名', lambda: self.ui('PID', 'Expand', 'Local process: python.exe')),
            (272, '单进程 TCP 流筛选', self.check_pid_view),
            (282, '请求响应统计', self.show_statistics),
            (296, '记录界面证据', lambda: self.ui('LABDEMO', 'Inspect')),
        ]
        self.timer = QTimer()
        self.timer.setInterval(40)
        self.timer.timeout.connect(self.tick)
        QTimer.singleShot(1500, self.begin)

    def log(self, name):
        packet = self.window.selected_packet()
        item = {'elapsed': round(time.monotonic() - self.started, 3), 'action': name,
                'rows': self.window.model.rowCount(), 'filter': self.window.display_filter.text(),
                'selected_packet': packet.raw.number if packet else None, 'window_rect': client_rectangle(int(self.window.winId()))}
        if self.window.engine:
            item['stats'] = self.window.engine.snapshot()
        self.events.append(item)
        (self.directory / 'events.json').write_text(json.dumps(self.events, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps({'elapsed': item['elapsed'], 'action': name}, ensure_ascii=False), flush=True)

    def begin(self):
        self.rectangle = client_rectangle(int(self.window.winId()))
        assert self.rectangle[2] >= 1280 and self.rectangle[3] >= 680
        if not self.args.rehearse:
            log = (self.directory / 'capture-ffmpeg.log').open('w', encoding='utf-8')
            self.logs.append(log)
            x, y, width, height = self.rectangle
            command = [str(self.args.ffmpeg), '-hide_banner', '-nostats', '-f', 'gdigrab', '-framerate', '25',
                       '-draw_mouse', '0', '-offset_x', str(x), '-offset_y', str(y), '-video_size', f'{width}x{height}',
                       '-i', 'desktop', '-t', '310', '-an', '-vf', 'setpts=PTS-STARTPTS,scale=-2:980,pad=1920:1080:(ow-iw)/2:0:color=0x111827',
                       '-c:v', 'libx264', '-preset', 'veryfast', '-tune', 'zerolatency', '-crf', '18', '-pix_fmt', 'yuv420p',
                       '-r', '25', '-fps_mode', 'cfr',
                       '-movflags', '+faststart', '-progress', 'pipe:1', str(self.directory / 'clean.mp4')]
            self.recording = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                                              text=True, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
            self.ready = threading.Event()
            def progress():
                for line in self.recording.stdout:
                    if line.startswith('frame=') and int(line.partition('=')[2]) > 0:
                        self.ready.set()
            threading.Thread(target=progress, daemon=True).start()
            if not self.ready.wait(8):
                raise RuntimeError('录屏工具未能输出实际画面')
        self.started = time.monotonic()
        self.log('开始演示')
        self.timer.start()

    def tick(self):
        elapsed = (time.monotonic() - self.started) / self.scale
        if self.cursor < len(self.steps) and elapsed >= self.steps[self.cursor][0]:
            _, name, action = self.steps[self.cursor]
            action()
            self.log(name)
            self.cursor += 1
        if elapsed >= 312:
            self.finish()

    def start_traffic(self):
        assert self.window.engine.ready.is_set() and not self.window.engine.error
        log = (self.directory / 'traffic.log').open('w', encoding='utf-8')
        self.logs.append(log)
        self.traffic = subprocess.Popen([sys.executable, str(ROOT / 'tools/demo_traffic.py'), str(self.directory / 'traffic.json')],
                                        cwd=ROOT, stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW)

    def select_packet(self, predicate=lambda packet: True, layer=None):
        for index, packet in enumerate(self.window.model.rows):
            if predicate(packet):
                self.window.table.selectRow(index)
                self.window.table.scrollTo(self.window.model.index(index, 0))
                if layer:
                    self.window.details.collapseAll()
                    for number in range(self.window.details.topLevelItemCount()):
                        node = self.window.details.topLevelItem(number)
                        if node.text(0).lower() == layer.lower():
                            node.setExpanded(True)
                            for child_index in range(node.childCount()):
                                node.child(child_index).setExpanded(True)
                            self.window.details.scrollToItem(node)
                return packet
        raise RuntimeError('当前过滤结果中没有需要展示的真实报文')

    def filter_packet(self, expression, predicate=lambda packet: True, layer=None):
        self.window.set_filter(expression)
        return self.select_packet(predicate, layer)

    def check_capture(self):
        assert self.traffic.poll() == 0, (self.directory / 'traffic.log').read_text(encoding='utf-8')
        self.traffic_info = json.loads((self.directory / 'traffic.json').read_text(encoding='utf-8'))
        assert self.window.engine.finished.is_set() and not self.window.engine.error
        self.window.refresh_packets()
        self.capture_stats = self.window.engine.snapshot()
        self.packet_count = self.window.model.rowCount()
        assert {'HTTP', 'TCP', 'UDP', 'LABDEMO', 'DNS', 'ICMP', 'ICMPv6'} <= {packet.protocol for packet in self.window.model.rows}
        assert len(self.window.analyzer.snapshot()) == 3
        self.select_packet(lambda packet: packet.protocol == 'TCP')

    def show_flows(self):
        self.window.workspace_tabs.setCurrentIndex(1)
        self.window.process_filter.clear()
        self.window.refresh_flows()
        assert self.window.flow_tree.topLevelItemCount() == 3

    def filter_process(self):
        self.window.process_filter.setText(str(self.traffic_info['pid']))
        self.window.refresh_flows()
        assert self.window.flow_tree.topLevelItemCount() == 3
        self.window.flow_tree.topLevelItem(0).setSelected(True)

    def show_flow(self):
        identifier = self.window.flow_tree.selectedItems()[0].data(0, Qt.UserRole)
        flow = self.window.analyzer.get(identifier)
        assert b'GET /split/' in flow['directions'][0]['data']
        self.dialog = FlowDialog(flow, self.window)
        self.dialog.setWindowFlag(Qt.WindowStaysOnTopHint, True)
        self.dialog.setGeometry(self.window.geometry())
        self.dialog.show()
        position_window(int(self.dialog.winId()), self.rectangle)
        self.dialog.http_tree.expandToDepth(2)
        self.dialog.process_tree.expandToDepth(1)

    def close_flow(self):
        self.dialog.close()
        self.dialog = None
        self.window.workspace_tabs.setCurrentIndex(0)
        self.filter_packet('http')

    def check_export(self):
        assert not self.window.export_thread.is_alive()
        self.metadata = load_metadata(self.export_path)
        assert self.metadata['packet_count'] == self.packet_count
        assert len(list(PcapFile.read(self.export_path))) == self.packet_count

    def check_reopen(self):
        assert self.window.engine.finished.is_set() and not self.window.engine.error
        self.window.set_filter('')
        self.window.refresh_packets()
        assert self.window.model.rowCount() == self.packet_count
        self.select_packet(lambda packet: packet.protocol == 'HTTP', 'HTTP')

    def launch_wireshark(self):
        config = {'capture': str(self.export_path), 'pid': self.traffic_info['pid'], 'packets': self.packet_count,
                  'result': str(self.directory / 'pid-fields.json')}
        (self.directory / 'observer.json').write_text(json.dumps(config, ensure_ascii=False), encoding='utf-8')
        self.metadata = load_metadata(self.export_path)
        demo_number = next(packet.raw.number for packet in self.window.model.rows if packet.protocol == 'LABDEMO')
        pid_number = next(item['original_number'] for item in self.metadata['packets'] if item['process']['owners'])
        for name, expression, selected in (('LABDEMO', 'labdemo', demo_number), ('PID', 'frame.number >= 1', pid_number)):
            settings = self.directory / f'settings_{name}'
            settings.mkdir()
            command = wireshark_arguments(self.export_path, gui=True)
            command += ['-n', '-Y', expression, '-g', str(selected), '-P', f'persconf:{settings}', '--temp-dir', str(self.directory),
                        '-o', f'gui.window_title:UCAS {name} actual recording', '-d', 'tcp.port==18080,http']
            if name == 'PID':
                command += ['-X', f'lua_script:{ROOT / "tools/video_pid_observer.lua"}', '-X', f'lua_script4:{self.directory / "observer.json"}',
                            '-o', 'gui.column.format:"No.","%m","Source","%s","Destination","%d","Stream","%Cus:tcp.stream","PID","%Cus:labproc.pid","Protocol","%p","Info","%i"']
            stdout = (self.directory / f'{name}.stdout.log').open('w', encoding='utf-8')
            stderr = (self.directory / f'{name}.stderr.log').open('w', encoding='utf-8')
            self.logs.extend((stdout, stderr))
            self.processes[name] = subprocess.Popen(command, cwd=ROOT, stdout=stdout, stderr=stderr)
        self.window.raise_()

    def front(self, name):
        process = self.processes[name]
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None, (self.directory / f'{name}.stderr.log').read_text(encoding='utf-8')
            windows = [handle for handle, title in windows_for(process.pid, include_hidden=True) if self.export_path.name in title]
            if windows:
                handle = windows[0]
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f'{name} 窗口没有完成抓包文件加载')
            time.sleep(0.1)
        position_window(handle, self.rectangle)
        for other_name, other_process in self.processes.items():
            if other_name != name:
                for other_handle, _ in windows_for(other_process.pid):
                    USER.ShowWindow(other_handle, 0)
        self.window.hide()
        self.ui(name, 'Inspect')

    def ui(self, name, action, value=''):
        output = self.directory / f'ui-{self.cursor:02d}-{name}.json'
        command = ['pwsh', '-NoProfile', '-File', str(ROOT / 'tools/video_ui.ps1'), '-ProcessId', str(self.processes[name].pid),
                   '-Action', action, '-Value', value, '-OutputFile', str(output)]
        # 辅助功能枚举会查询本窗口，等待期间继续处理 Qt 消息。
        self.timer.stop()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', errors='replace',
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        deadline = time.monotonic() + 15
        while process.poll() is None:
            self.app.processEvents()
            if time.monotonic() >= deadline:
                process.kill()
                process.communicate()
                raise TimeoutError('Wireshark 辅助功能操作超时')
            time.sleep(0.02)
        stdout, stderr = process.communicate()
        self.timer.start()
        if process.returncode:
            raise RuntimeError(stdout + stderr)
        main_handle = next(handle for handle, title in windows_for(self.processes[name].pid) if self.export_path.name in title)
        assert client_rectangle(main_handle) == self.rectangle
        return json.loads(output.read_text(encoding='utf-8-sig'))

    def check_pid_view(self):
        record = json.loads((self.directory / 'pid-fields.json').read_text(encoding='utf-8'))
        expected = sum(any(owner['pid'] == self.traffic_info['pid'] for owner in item['process']['owners'])
                       for item in self.metadata['packets'])
        assert record['matched'] == expected and len(record['streams']) == 3, record
        self.pid_record = record
        self.ui('PID', 'LastPacket')

    def show_statistics(self):
        self.front('LABDEMO')
        state = self.ui('LABDEMO', 'Statistics')
        text = next(item['Value'] for item in state['Controls'] if 'LABDEMO_STATS requests=' in item['Value'])
        assert 'requests=3 responses=3 pairs=2 errors=1 invalid=2' in text and 'timeout=1' in text, text
        self.statistics = text
        windows = windows_for(self.processes['LABDEMO'].pid)
        dialog = next(handle for handle, title in windows if 'LABDEMO request response statistics' in title)
        position_window(dialog, self.rectangle)

    def finish(self):
        self.timer.stop()
        if self.recording:
            assert self.recording.wait(15) == 0
        for name in self.processes:
            assert not (self.directory / f'{name}.stderr.log').read_text(encoding='utf-8').strip()
        result = {'status': 'PASS', 'rehearsal': self.args.rehearse, 'directory': str(self.directory), 'packets': self.packet_count,
                  'traffic_pid': self.traffic_info['pid'], 'capture': str(self.export_path), 'pid': self.pid_record,
                  'statistics': self.statistics, 'capture_stats': self.capture_stats, 'rectangle': self.rectangle,
                  'events': len(self.events), 'duration_target': 310, 'gui_processes': {name: process.pid for name, process in self.processes.items()}}
        (self.directory / 'recording-result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        for process in self.processes.values():
            for handle, _ in windows_for(process.pid):
                USER.SetWindowPos(handle, -2, 0, 0, 0, 0, 3)
        self.window.setWindowFlag(Qt.WindowStaysOnTopHint, False)
        self.window.close()
        self.app.quit()

    def fail(self, kind, value, trace):
        message = ''.join(traceback.format_exception(kind, value, trace))
        logging.error(message)
        (self.directory / 'failure.txt').write_text(message, encoding='utf-8')
        print(message, file=sys.stderr, flush=True)
        self.timer.stop()
        if self.recording and self.recording.poll() is None:
            self.recording.stdin.write('q\n')
            self.recording.stdin.flush()
        if self.window.engine:
            self.window.engine.stop()
            self.window.engine.wait(5)
        if self.window.tracker:
            self.window.tracker.stop()
        for process in self.processes.values():
            for handle, _ in windows_for(process.pid):
                USER.SetWindowPos(handle, -2, 0, 0, 0, 0, 3)
        self.app.exit(1)


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser()
    parser.add_argument('--ffmpeg', type=Path, default=ROOT / '.work/ffmpeg/ffmpeg-9.0.2-essentials_build/bin/ffmpeg.exe')
    parser.add_argument('--rehearse', action='store_true')
    args = parser.parse_args()
    app = QApplication([])
    demonstration = Demonstration(app, args)
    sys.excepthook = demonstration.fail
    raise SystemExit(app.exec())


if __name__ == '__main__':
    main()
