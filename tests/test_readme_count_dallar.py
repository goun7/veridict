"""G34-pini: README'nin test-sayisi-iddiasi gercek-collect'e-esit.

Bu-pın, 2026-10-19-bulgusunu-kapatir: README "1.867 collected" diyordu,
gercek-collect 1871 idi ( 4-test-eklenmisti-ve-README-cürümüstü).

Kural ( G27/G28-deseni-ile-ayni): README'deki-collected-sayisi ile
pytest-bootstrap-sayisi-ayni-degilse-KIRMIZI. README-nin-soyledigi-ile
olctugumuz-ayni-olmali-("tamamlanma"-olcutumuz-bu).
"""
import re
import subprocess
import sys
from pathlib import Path


def test_readme_test_count_is_not_stale():
    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    m = re.search(r"([\d.,]+)\s*collected", readme)
    assert m, "README-collected-satiri-bulunamadi"
    claimed = int(m.group(1).replace(".", "").replace(",", ""))
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
        capture_output=True, text=True, cwd=str(root), timeout=600)
    assert res.returncode == 0, res.stderr[-400:]
    num = None
    for ln in res.stdout.splitlines():
        mm = re.search(r"(\d+)\s*tests?\s*collected", ln)
        if mm:
            num = int(mm.group(1))
    assert num is not None, "collect-total-ayristirilamadi: %r" % res.stdout[-300:]
    assert num == claimed, (
        "README-stale-test-sayisi: iddia=%d gercek=%d" % (claimed, num))
