import uuid

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from labsniffer.capture import CaptureEngine
from labsniffer.models import RawPacket
from labsniffer.protocols import parse_packet
from labsniffer.storage import SessionWriter, export_session, load_metadata


def test_original_numbers_and_session_survive_reopen(evidence_dir):
    directory = evidence_dir / str(uuid.uuid4())
    writer = SessionWriter(directory, 1)
    for number in (2, 5, 8):
        data = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP() / UDP())
        writer.append(parse_packet(RawPacket(number, 1_790_000_000_000_000_000 + number, data, len(data), 1)))
    writer.close()
    first, _ = export_session(directory, evidence_dir / f"original_{uuid.uuid4().hex}.pcap")
    engine = CaptureEngine(evidence_dir, source=first, parser=parse_packet)
    engine.start()
    engine.wait(5)
    assert not engine.error, engine.error
    second, _ = export_session(engine.directory, evidence_dir / f"reopened_{uuid.uuid4().hex}.pcap")
    a, b = load_metadata(first), load_metadata(second)
    assert a == b
    assert [item["original_number"] for item in b["packets"]] == [2, 5, 8]
