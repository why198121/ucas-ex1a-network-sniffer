import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import textwrap


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from labsniffer.cli import find_wireshark


def verify_capture(directory, recording):
    capture = Path(recording['capture'])
    command = [str(find_wireshark('tshark.exe')), '-2', '-R', 'frame.number >= 1', '-r', str(capture),
               '-o', f'labproc.metadata:{capture}.labproc.json', '-o', f'labproc.capture:{capture}',
               '-d', 'tcp.port==18080,http', '-T', 'fields', '-E', 'separator=,', '-E', 'quote=d']
    for script in ('labdemo.lua', 'labproc.lua'):
        command += ['-X', f'lua_script:{ROOT / "wireshark" / script}']
    fields = ['frame.number', 'labdemo.request_id', 'labdemo.valid', 'labproc.pid', 'tcp.stream', 'http.request.method', '_ws.lua.error']
    for field in fields:
        command += ['-e', field]
    result = subprocess.run(command, capture_output=True, encoding='utf-8', timeout=45)
    (directory / 'tshark-fields.csv').write_text(result.stdout, encoding='utf-8')
    (directory / 'tshark-verification.json').write_text(json.dumps({'command': command, 'returncode': result.returncode,
        'stderr': result.stderr, 'fields': fields}, ensure_ascii=False, indent=2), encoding='utf-8')
    assert result.returncode == 0 and not result.stderr, result.stderr
    rows = list(csv.reader(io.StringIO(result.stdout)))
    assert len(rows) == recording['packets'] and all(len(row) == len(fields) and not row[-1] for row in rows)
    matching = [row for row in rows if str(recording['traffic_pid']) in row[3].split(',')]
    streams = sorted({row[4] for row in matching})
    assert len(matching) == recording['pid']['matched'] and streams == recording['pid']['streams']
    demo_count = sum(bool(row[1]) for row in rows)
    http_count = sum(row[5] == 'GET' for row in rows)
    assert demo_count == 8 and http_count == 3
    assert sum(row[1] == '1001' for row in rows) == 2
    assert sum(row[2] == 'False' for row in rows) == 2
    return {'status': 'PASS', 'packets': len(rows), 'pid_packets': len(matching), 'streams': streams,
            'labdemo_packets': demo_count, 'http_requests': http_count, 'lua_errors': 0}


def timecode(seconds, ass=False):
    whole = int(seconds)
    hours, remainder = divmod(whole, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f'{hours}:{minutes:02d}:{seconds:02d}.00' if ass else f'{hours:02d}:{minutes:02d}:{seconds:02d},000'


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--ffmpeg', type=Path, default=ROOT / '.work/ffmpeg/ffmpeg-9.0.2-essentials_build/bin/ffmpeg.exe')
    args = parser.parse_args()
    directory = (args.directory or Path(json.loads((ROOT / '.work/video-current.json').read_text(encoding='utf-8'))['directory'])).resolve()
    recording = json.loads((directory / 'recording-result.json').read_text(encoding='utf-8'))
    assert recording['status'] == 'PASS' and not recording['rehearsal']
    events = json.loads((directory / 'events.json').read_text(encoding='utf-8'))
    assert len(events) >= 45 and events[-1]['elapsed'] >= 296
    comparison = verify_capture(directory, recording)
    narration = json.loads((ROOT / 'docs/demo_narration.json').read_text(encoding='utf-8'))
    srt, spoken = [], ['实验 1A 演示配音稿', '视频时长：5 分 10 秒；以下文本可按时间段录音。', '']
    shots = ['# 演示镜头与 PDF 要求对应', '', '视频来自真实应用运行；操作由演示脚本控制，网络流量在本机生成。', '',
             '| 时间 | PDF 页码 / 性质 | 画面与讲解 |', '| --- | --- | --- |']
    ass = ['[Script Info]', 'ScriptType: v4.00+', 'PlayResX: 1920', 'PlayResY: 1080', 'WrapStyle: 2', '',
           '[V4+ Styles]', 'Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding',
           'Style: Default,Microsoft YaHei UI,34,&H00FFFFFF,&H00FFFFFF,&H00111827,&H00111827,0,0,0,0,100,100,0,0,1,1,0,2,80,80,12,1', '',
           '[Events]', 'Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text']
    for index, item in enumerate(narration, 1):
        text = item['text'].format(packets=recording['packets'])
        lines = textwrap.wrap(text, width=44)
        assert len(lines) <= 2, text
        start, end = timecode(item['start']), timecode(item['end'])
        srt.extend([str(index), f'{start} --> {end}', '\n'.join(lines), ''])
        spoken.extend([f'{start[:8]}—{end[:8]}', text, ''])
        shots.append(f"| {start[3:8]}–{end[3:8]} | {item['page']} | {text} |")
        rendered = r'\N'.join(lines)
        ass.append(f"Dialogue: 0,{timecode(item['start'], True)},{timecode(item['end'], True)},Default,,0,0,0,,{rendered}")
    subtitle = directory / '演示字幕.srt'
    voiceover = directory / '配音稿.txt'
    mapping = directory / '镜头与PDF对应表.md'
    subtitle.write_text('\n'.join(srt), encoding='utf-8-sig')
    voiceover.write_text('\n'.join(spoken), encoding='utf-8-sig')
    mapping.write_text('\n'.join(shots) + '\n', encoding='utf-8')
    (directory / 'captions.ass').write_text('\n'.join(ass) + '\n', encoding='utf-8-sig')
    output = directory / '姓名待填写_学号待填写_ex1A_play.mp4'
    command = [str(args.ffmpeg), '-y', '-hide_banner', '-nostats', '-i', 'clean.mp4', '-vf', 'ass=captions.ass',
               '-c:v', 'libx264', '-preset', 'fast', '-crf', '18', '-pix_fmt', 'yuv420p', '-an', '-movflags', '+faststart', str(output)]
    with (directory / 'subtitle-render.log').open('w', encoding='utf-8') as log:
        subprocess.run(command, cwd=directory, stdout=log, stderr=log, check=True)
    probe_command = [str(args.ffmpeg.with_name('ffprobe.exe')), '-v', 'error', '-count_frames', '-show_streams', '-show_format', '-of', 'json', str(output)]
    probe = subprocess.run(probe_command, capture_output=True, encoding='utf-8', check=True)
    info = json.loads(probe.stdout)
    (directory / 'ffprobe.json').write_text(probe.stdout, encoding='utf-8')
    video = next(stream for stream in info['streams'] if stream['codec_type'] == 'video')
    duration = float(info['format']['duration'])
    assert 309.5 <= duration <= 310.5, duration
    assert (video['width'], video['height']) == (1920, 1080)
    assert video['codec_name'] == 'h264' and video['r_frame_rate'] == '25/1'
    assert int(video['nb_read_frames']) >= 7740
    decoded = subprocess.run([str(args.ffmpeg), '-v', 'error', '-xerror', '-i', str(output), '-map', '0:v:0', '-f', 'null', 'NUL'],
                             capture_output=True, encoding='utf-8', timeout=180)
    (directory / 'decode.log').write_text(decoded.stdout + decoded.stderr, encoding='utf-8')
    assert decoded.returncode == 0 and not decoded.stderr, decoded.stderr
    black = subprocess.run([str(args.ffmpeg), '-hide_banner', '-i', str(output), '-vf', 'blackdetect=d=0.5:pix_th=0.10',
                           '-an', '-f', 'null', 'NUL'], capture_output=True, encoding='utf-8', errors='replace', timeout=180)
    (directory / 'black-detection.log').write_text(black.stderr, encoding='utf-8')
    assert black.returncode == 0 and 'black_start:' not in black.stderr
    result = {'status': 'PASS', 'directory': str(directory), 'video': str(output), 'clean_video': str(directory / 'clean.mp4'),
              'subtitles': str(subtitle), 'voiceover': str(voiceover), 'mapping': str(mapping),
              'duration_seconds': duration, 'resolution': [video['width'], video['height']], 'fps': video['r_frame_rate'],
              'frames': int(video['nb_read_frames']), 'subtitle_segments': len(narration), 'actual_capture': recording['capture'],
              'traffic_pid': recording['traffic_pid'], 'packets': recording['packets'], 'pid_streams': recording['pid']['streams'],
              'capture_crosscheck': comparison,
              'video_sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
              'checks': ['真实运行事件日志', '真实 PCAP/PID 配对', 'GUI 字段与 Listener 统计', '同文件 TShark 字段对照', '字幕生成', '全片解码', '时长与分辨率', '无持续黑屏'],
              'visual_review': '未进行人工逐帧视觉审核；依照用户限制使用控件状态、运行日志和视频解码检查。'}
    (directory / 'video-check.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    (ROOT / 'output/video/latest.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
