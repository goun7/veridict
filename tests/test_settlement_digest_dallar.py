"""Veridict settlement._claim_digest dal-kesen testleri (LEED).

Kural-1: MEVCUT DOSYALARA DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (sha256/json — dis cagri YOK).
_claim_digest: _DIGEST_FIELDS'in her biri sha256-preimage'ina girer;
EKSIK anahtar -> None, FAZLA anahtar -> gozardi, anahtar-SIRASI bagimsiz.
"""
import hashlib
import json
import sys

import pytest

sys.path.insert(0, ".")
from veridict.settlement import _claim_digest, _DIGEST_FIELDS  # noqa: E402

_BASE = {"cert_id": "c", "task_id": "t", "artifact_digest": "a", "valid": True,
         "reasons": [], "accepted_claims": 1, "total_claims": 2,
         "jury_families": 3, "risk_level": "low", "policy_digest": "p"}


def _expected(fields: dict) -> str:
    body = {k: fields.get(k) for k in _DIGEST_FIELDS}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# == temel davranis =============================================================================

def test_tam_alan():
    """ORTAM: tum _DIGEST_FIELDS mevcut -> sha256-hex 64-karakter."""
    out = _claim_digest(_BASE)
    assert out == _expected(_BASE)
    assert len(out) == 64
    assert all(c in "0123456789abcdef" for c in out)


def test_alan_listesi_sabit():
    """ORTAM-ANATOMI: 10 alan, alfabe-sirali degil, TANIMLANMIS sira uzerinde."""
    assert _DIGEST_FIELDS == ("cert_id", "task_id", "artifact_digest", "valid",
                              "reasons", "accepted_claims", "total_claims",
                              "jury_families", "risk_level", "policy_digest")


@pytest.mark.parametrize("key", list(_DIGEST_FIELDS))
def test_her_alan_preimage_girer(key):
    """ORTAM: her alani degistirmek digest'i DEGISTIRIR — hicbiri kozmetik degil."""
    base = dict(_BASE)
    before = _claim_digest(base)
    base[key] = "MUTATED-VALUE" if not isinstance(base[key], (int, bool)) else base[key] + 7
    assert _claim_digest(base) != before


@pytest.mark.parametrize("key", list(_DIGEST_FIELDS))
def test_alan_silince_none(key):
    """ORTAM-OGRENDI: EKSIK alan -> .get(k) = None ile serilesir; digest degisir."""
    base = dict(_BASE)
    before = _claim_digest(base)
    del base[key]
    after = _claim_digest(base)
    assert after != before
    assert after == _expected(base)


# == fazla anahtar / siparis ====================================================================

@pytest.mark.parametrize("extra", [
    {"extra": "x"},
    {"nonce": 12345},
    {"unknown": None},
    {"sig": "deadbeef", "memo": "note"},
])
def test_fazla_anahtar_gozardi(extra):
    """ORTAM-OGRENDI: _DIGEST_FIELDS disindaki her sey gozardi edilir —
    digest yalnizca baglayici alanlari kor."""
    with_extra = {**_BASE, **extra}
    assert _claim_digest(with_extra) == _claim_digest(_BASE)


@pytest.mark.parametrize("reordered", [
    {"policy_digest": "p", "risk_level": "low", "jury_families": 3,
     "total_claims": 2, "accepted_claims": 1, "reasons": [],
     "valid": True, "artifact_digest": "a", "task_id": "t", "cert_id": "c"},
    {"risk_level": "low", "cert_id": "c", "accepted_claims": 1},
])
def test_anahtar_sirasi_bagimsiz(reordered):
    """ORTAM: sort_keys=True -> ayni icerik her sirada ayni digest (kanonik)."""
    merged = {**_BASE, **reordered}
    assert _claim_digest(merged) == _claim_digest(_BASE)


# == hucre alistirma ============================================================================

@pytest.mark.parametrize("value", [
    "cert-x", "", "with spaces", "unicode-😀", 0, 42, True, False, None,
    [], ["a"], {}, {"k": "v"},
])
def test_alan_degeri_tipleri(value):
    """ORTAM: her hucresel tip JSON-serializable oldugu surece kabul."""
    base = dict(_BASE)
    base["cert_id"] = value
    assert _claim_digest(base) == _expected(base)


@pytest.mark.parametrize("valid", [True, False])
def test_boolean_alan_ayri_digerli(valid):
    """ORTAM: valid True/False farkli digest — boolean serilesme kullanilir."""
    base = dict(_BASE)
    base["valid"] = valid
    assert _claim_digest(base) == _expected(base)


def test_deger_fretilari_farkli():
    """ORTAM: reasons listesi [] vs ['x'] farkli digest — icerik tam kapsanir."""
    a = dict(_BASE); a["reasons"] = []
    b = dict(_BASE); b["reasons"] = ["nope"]
    assert _claim_digest(a) != _claim_digest(b)


# == sinir / hata yollari =======================================================================

def test_bos_dict():
    """ORTAM: {} -> tum alanlar None; yine de gecerli 64-hex doner."""
    out = _claim_digest({})
    assert out == _expected({})
    assert len(out) == 64


@pytest.mark.parametrize("bad", [None, [1, 2], "str", 42, ("a", "b")])
def test_dict_disi_girdi(bad):
    """ORTAM-OGRENDI: dict'ten baska tip -> AttributeError('.get' yok);
    sessiz ceviri YAPILMAZ, hata fail-loud."""
    with pytest.raises(AttributeError):
        _claim_digest(bad)


def test_deterministik():
    """ORTAM: ayni girdi tekrar tekrar ayni digest."""
    first = _claim_digest(_BASE)
    assert _claim_digest(_BASE) == first
    assert _claim_digest(_BASE) == first


def test_ham_preimage_yapisi():
    """ORTAM: digest, json.dumps(sort_keys, separators) ile birebir
    yeniden hesaplanabilir — sasiirma/duzeltme olmadan."""
    body = {k: _BASE.get(k) for k in _DIGEST_FIELDS}
    assert _claim_digest(_BASE) == hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_komşu_deger_ayrimi():
    """ORTAM: yakindeki degerler farkli digest verir (cakisma direnci)."""
    a = dict(_BASE); a["total_claims"] = 2
    b = dict(_BASE); b["total_claims"] = 3
    assert _claim_digest(a) != _claim_digest(b)
    c = dict(_BASE); c["cert_id"] = "c0"
    d = dict(_BASE); d["cert_id"] = "c1"
    assert _claim_digest(c) != _claim_digest(d)


@pytest.mark.parametrize("key", ["cert_id", "policy_digest", "artifact_digest"])
def test_bos_string_alan(key):
    """ORTAM: '' gecerli (None degil) — .get() yalnizca YOKlukta None doner."""
    base = dict(_BASE)
    base[key] = ""
    assert _claim_digest(base) == _expected(base)
    assert _claim_digest(base) != _claim_digest(_BASE)
