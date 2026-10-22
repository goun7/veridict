"""A1c-2026-10-22: surum-tek-kaynak pin'leri ( veridict).

Onceki-tasarim ( importlib.metadata-only, export.py:_veridict_version)
kaynak-agacinda-YALAN-soyluyordu: site-packages'taki ESKI-kurulu-paketi
buluyordu, bu-deponin-pyproject'ini-degil. Dist-adi-ayri-tuzak: pyproject
"veridict-standard"-dir, bare-"veridict"-baskasina-aittir.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"


def _pyproject_version() -> str:
    """pyproject.toml'den TEK version satirini-okur."""
    metin = PYPROJECT.read_text(encoding="utf-8")
    satirlar = [ln for ln in metin.splitlines() if re.match(r"^version\s*=", ln)]
    assert len(satirlar) == 1, f"pyproject version-satiri-1-olmali, bulundu={len(satirlar)}"
    return satirlar[0].split('"')[1]


def test_init_version_pyproject_ile_ayni():
    """veridict.__version__ pyproject.toml version'ina-esit ( tek-kaynak)."""
    from veridict import __version__

    assert __version__ == _pyproject_version(), (
        f"surum-celiskisi: __init__={__version__!r} pyproject={_pyproject_version()!r}"
    )


def test_export_version_pyproject_ile_ayni():
    """export._veridict_version() pyproject version'ina-esit."""
    from veridict.export import _veridict_version

    assert _veridict_version() == _pyproject_version(), (
        f"surum-celiskisi: export={_veridict_version()!r} pyproject={_pyproject_version()!r}"
    )


def test_export_version_init_ile_ayni_nesne():
    """export._veridict_version() veridict.__version__-dir ( SAME nesne)."""
    from veridict import __version__
    from veridict.export import _veridict_version

    assert _veridict_version() is __version__


def test_cli_version_flag_pyproject_ile_ayni():
    """`veridict --version` ciktisi pyproject version'ini-icerir."""
    surum = _pyproject_version()
    res = subprocess.run(
        [sys.executable, "-m", "veridict.cli", "--version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert res.returncode == 0, f"rc={res.returncode} stderr={res.stderr[-300:]}"
    assert surum in res.stdout, f"--version-ciktisi-yanlis: {res.stdout.strip()!r}"
