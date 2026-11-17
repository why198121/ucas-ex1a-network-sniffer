from pathlib import Path

import pytest


@pytest.fixture
def evidence_dir():
    directory = Path(__file__).resolve().parents[1] / ".work" / "test-evidence"
    directory.mkdir(parents=True, exist_ok=True)
    return directory
