"""Veridict — the verdict that survived verification."""

# A1c-2026-10-22: surum-TEK-KAYNAKLI ( pyproject.toml). Oncesi-tasarim
# ( importlib.metadata-only, export.py:_veridict_version) kaynak-agacinda
# YALAN-SOYLEYORDU: site-packages'taki-ESKI-kurulu-paketi-buluyordu,
# bu-deponin-pyproject'ini-degil. Dist-adi-ayri-bir-tuzak: pyproject
# "veridict-standard"-dir-ama-bare-"veridict"-baskasina-aittir.
# Duzeltme: once-kaynak-pyproject-okunur, YOKSA-importlib'ye-dusulur.
from pathlib import Path

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _kaynak_surumu():
    """Kaynak-agacindaki-pyproject.toml'den-version-okur ( yoksa-None)."""
    if not _PYPROJECT.exists():
        return None
    for ln in _PYPROJECT.read_text(encoding="utf-8").splitlines():
        if ln.startswith("version ="):
            return ln.split('"')[1]
    return None


_KAYNAK = _kaynak_surumu()
if _KAYNAK is not None:
    __version__ = _KAYNAK
else:
    try:
        from importlib.metadata import PackageNotFoundError
        from importlib.metadata import version as _dist_v

        for _dist in ("veridict-standard", "veridict"):
            try:
                __version__ = _dist_v(_dist)
                break
            except PackageNotFoundError:
                continue
        else:
            __version__ = "0.0.0-dev"
    except (ImportError, ModuleNotFoundError):
        __version__ = "0.0.0-dev"

__all__ = ["__version__"]
