from pathlib import Path

import pytest

from labsniffer.models import RawPacket
from labsniffer.storage import PcapFile


@pytest.mark.parametrize("linktype", [0, 1, 101, 108])
def test_pcap_preserves_original_lengths_and_time(tmp_path, linktype):
    path = tmp_path / "truncated.pcap"
    packet = RawPacket(1, 1_790_000_000_123_456_000, b"abcd", 64, linktype)
    with PcapFile.writer(path, linktype) as writer:
        writer.append(packet)
    result = list(PcapFile.read(path))
    assert result == [packet]


def test_corrupt_file_rejected(tmp_path):
    path = tmp_path / "broken.pcap"
    path.write_bytes(b"not a capture")
    with pytest.raises(ValueError, match="PCAP"):
        list(PcapFile.read(path))
