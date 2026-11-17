import hashlib
import gzip
import json
import shutil
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from scapy.utils import RawPcapReader, RawPcapWriter
from scapy.error import Scapy_Exception

from .models import RawPacket


MAX_CAPTURE_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024 * 1024


def digest_file(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


class PcapFile:
    @staticmethod
    @contextmanager
    def writer(path, linktype):
        writer = RawPcapWriter(str(path), linktype=101 if linktype == 12 else linktype, nano=True, snaplen=262144)
        # Scapy 构造函数以真值检查 linktype；DLT_NULL 的数值为零，需要显式保留。
        writer.linktype = 101 if linktype == 12 else linktype
        writer.write_header(None)

        class Sink:
            def append(self, packet):
                if (101 if packet.linktype == 12 else packet.linktype) != writer.linktype:
                    raise ValueError("同一 PCAP 文件只能保存一种链路类型")
                seconds, nanoseconds = divmod(packet.timestamp_ns, 1_000_000_000)
                writer.write_packet(packet.data, sec=seconds, usec=nanoseconds,
                                    caplen=packet.caplen, wirelen=packet.wirelen)

        try:
            yield Sink()
        finally:
            writer.close()

    @staticmethod
    def read(path):
        path = Path(path)
        size = path.stat().st_size
        if size > MAX_CAPTURE_BYTES:
            raise ValueError("PCAP 超出本程序 256 MiB 单会话上限")
        try:
            with RawPcapReader(str(path)) as reader:
                if isinstance(reader.f, gzip.GzipFile):
                    raise ValueError("请先解压缩 PCAP 文件")
                if type(reader) is not RawPcapReader:
                    raise ValueError("仅支持标准 PCAP；PCAPNG 请使用 editcap -F pcap 转换")
                if not 1 <= reader.snaplen <= 262144:
                    raise ValueError("PCAP snaplen 超出支持范围")
                number = 0
                while reader.f.tell() < size:
                    if size - reader.f.tell() < 16:
                        raise ValueError("PCAP 包记录头被截断")
                    data, metadata = reader._read_packet(size=262144)
                    if len(data) != metadata.caplen or metadata.caplen > metadata.wirelen:
                        raise ValueError("PCAP 包记录长度损坏")
                    resolution = 1_000_000_000 if reader.nano else 1_000_000
                    if metadata.usec >= resolution:
                        raise ValueError("PCAP 时间戳小数部分非法")
                    number += 1
                    yield RawPacket(number, metadata.sec * 1_000_000_000 + metadata.usec * (1 if reader.nano else 1000),
                                    data, metadata.wirelen, reader.linktype)
        except (Scapy_Exception, EOFError, OSError) as error:
            raise ValueError(f"无法读取 PCAP：{error}") from error


class SessionWriter:
    def __init__(self, directory, linktype, session_id=None):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.session_id = session_id or str(uuid.uuid4())
        self.linktype = linktype
        self.pcap = self.directory / "capture.pcap"
        self.db = sqlite3.connect(self.directory / "metadata.sqlite")
        self.db.execute("CREATE TABLE packets(frame INTEGER PRIMARY KEY, original INTEGER NOT NULL, metadata TEXT NOT NULL)")
        self.db.execute("CREATE TABLE session(id TEXT NOT NULL, linktype INTEGER NOT NULL)")
        self.db.execute("INSERT INTO session VALUES(?,?)", (self.session_id, linktype))
        self.count = 0
        self.bytes = 24
        self.context = PcapFile.writer(self.pcap, linktype)
        self.writer = self.context.__enter__()

    def append(self, packet):
        raw = packet.raw
        if self.bytes + 16 + raw.caplen > MAX_CAPTURE_BYTES:
            raise ValueError("已达到 256 MiB 会话磁盘上限，捕获停止；请开始新会话")
        self.writer.append(raw)
        self.count += 1
        self.bytes += 16 + raw.caplen
        metadata = {"original_number": raw.number, "timestamp_ns": str(raw.timestamp_ns), "caplen": raw.caplen,
                    "wirelen": raw.wirelen, "sha256": hashlib.sha256(raw.data).hexdigest(),
                    "process": packet.process, "stream_id": packet.stream_id}
        self.db.execute("INSERT INTO packets VALUES(?,?,?)", (self.count, raw.number, json.dumps(metadata, ensure_ascii=False)))
        if self.count % 100 == 0:
            self.db.commit()

    def close(self):
        self.context.__exit__(None, None, None)
        self.db.commit()
        self.db.close()


def export_session(directory, destination):
    directory, destination = Path(directory), Path(destination)
    if destination.exists() or destination.with_suffix(destination.suffix + ".labproc.json").exists():
        raise ValueError("导出目标已存在，请选择新的文件名")
    source = directory / "capture.pcap"
    connection = sqlite3.connect(f"{(directory / 'metadata.sqlite').as_uri()}?mode=ro", uri=True)
    session_id, linktype = connection.execute("SELECT id,linktype FROM session").fetchone()
    count = connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    manifest = {"schema": 1, "session_id": session_id, "pcap_sha256": digest_file(source),
                "linktype": 101 if linktype == 12 else linktype, "packet_count": count}
    metadata_path = destination.with_suffix(destination.suffix + ".labproc.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with metadata_path.open("x", encoding="utf-8") as output:
            prefix = json.dumps(manifest, ensure_ascii=False)
            output.write(prefix[:-1] + ', "packets": [')
            for index, row in enumerate(connection.execute("SELECT metadata FROM packets ORDER BY frame")):
                if index:
                    output.write(",")
                output.write(row[0])
                if output.tell() > MAX_METADATA_BYTES:
                    raise ValueError("进程元数据超过 64 MiB 支持上限")
            output.write("]}")
        shutil.copyfile(source, destination)
    except BaseException:
        if metadata_path.exists():
            metadata_path.unlink()
        raise
    finally:
        connection.close()
    return destination, metadata_path


def load_metadata(pcap):
    pcap = Path(pcap)
    path = pcap.with_suffix(pcap.suffix + ".labproc.json")
    if not path.exists():
        return None
    if path.stat().st_size > MAX_METADATA_BYTES:
        raise ValueError("配套元数据超出 64 MiB 上限")
    metadata = json.loads(path.read_text(encoding="utf-8"))
    if metadata.get("schema") != 1 or metadata.get("pcap_sha256") != digest_file(pcap):
        raise ValueError("抓包文件与进程元数据配对校验失败")
    if metadata.get("packet_count") != len(metadata.get("packets", [])):
        raise ValueError("进程元数据包数不一致")
    uuid.UUID(metadata["session_id"])
    previous = 0
    for record in metadata["packets"]:
        if not isinstance(record, dict) or not isinstance(record.get("original_number"), int) or record["original_number"] <= previous:
            raise ValueError("进程元数据原始包号必须严格递增")
        previous = record["original_number"]
        if not isinstance(record.get("process"), dict) or not isinstance(record["process"].get("status"), str) or not isinstance(record["process"].get("owners"), list):
            raise ValueError("进程元数据缺少关联状态")
    return metadata
