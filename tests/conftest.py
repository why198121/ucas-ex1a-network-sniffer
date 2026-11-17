from pathlib import Path
import os
import uuid

import pytest


def pytest_configure(config):
    root = Path(__file__).resolve().parents[1]
    if not config.option.basetemp:
        config.option.basetemp = str(root / ".work" / f"pytest-{uuid.uuid4().hex}")
    # 解压后的工程也要先建立隔离目录，pytest 只负责创建其最终一级目录。
    Path(config.option.basetemp).resolve().parent.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def evidence_dir():
    directory = Path(os.environ.get("LAB_EVIDENCE_DIR", Path(__file__).resolve().parents[1] / ".work" / "test-evidence"))
    directory.mkdir(parents=True, exist_ok=True)
    return directory
