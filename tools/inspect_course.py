import json
import platform
import sys
from pathlib import Path

from pypdf import PdfReader


sys.stdout.reconfigure(encoding="utf-8")
root = Path(__file__).resolve().parents[1]
target = root / ".work"
target.mkdir(exist_ok=True)
reader = PdfReader(root / "实验 1 讲解 2026.pdf")
pages = [{"page": i + 1, "text": page.extract_text()} for i, page in enumerate(reader.pages)]
(target / "course_pages.json").write_text(json.dumps(pages, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps({"python": sys.version, "platform": platform.platform(), "pages": len(pages)}, ensure_ascii=False))
for page in pages:
    print(f"\n===== PDF 第 {page['page']} 页 =====\n{page['text']}")
