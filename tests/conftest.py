from pathlib import Path
import os

import pytest


@pytest.fixture
def evidence_dir():
    directory = Path(os.environ.get("LAB_EVIDENCE_DIR", Path(__file__).resolve().parents[1] / ".work" / "test-evidence"))
    directory.mkdir(parents=True, exist_ok=True)
    return directory
