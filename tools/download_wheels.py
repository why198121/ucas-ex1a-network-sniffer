import json
import subprocess
import sys
from pathlib import Path

from packaging.tags import sys_tags
from packaging.utils import parse_wheel_filename


root = Path(__file__).resolve().parents[1] / ".work" / "wheels"
root.mkdir(parents=True, exist_ok=True)
tags = set(sys_tags())
packages = sys.argv[1:]
for package in packages:
    metadata = root / f"{package}.json"
    subprocess.run(["curl.exe", "-4", "--retry", "2", "--retry-all-errors", "--fail", "--silent", "--show-error", "--location", "--max-time", "60",
                    f"https://pypi.org/pypi/{package}/json", "-o", str(metadata)], check=True)
    info = json.loads(metadata.read_text(encoding="utf-8"))
    choices = []
    for item in info["urls"]:
        if item["filename"].endswith(".whl") and not item["yanked"]:
            if parse_wheel_filename(item["filename"])[3] & tags:
                choices.append(item)
    if not choices:
        raise RuntimeError(f"没有兼容的 wheel: {package}")
    item = choices[0]
    destination = root / item["filename"]
    subprocess.run(["curl.exe", "-4", "--retry", "2", "--retry-all-errors", "--fail", "--silent", "--show-error", "--location", "--max-time", "300",
                    item["url"], "-o", str(destination)], check=True)
    import hashlib

    if hashlib.sha256(destination.read_bytes()).hexdigest() != item["digests"]["sha256"]:
        raise RuntimeError(f"SHA256 校验失败: {destination.name}")
    print(destination.name, flush=True)
