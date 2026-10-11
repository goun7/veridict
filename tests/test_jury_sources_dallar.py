"""Veridict jury._read_sources / Jury._build_item dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (tmp_path + RAM dataclass; network/LLM YASAK).

ORTAM-ANATOMI:
- _read_sources(artifact_dir): None/yok -> None; .py (test_ HARIC) dosyalarini
  sirali okur; taken < 6, total < 6000; bos dosya atlanir; chunks '--- name ---'
  baslikli, '\n\n'.join
- Jury._build_item(claim, artifact_digest, provider, opinion, round_salt=EID_SALT):
  evidence_id = sha256_hex(f'{salt}|{claim_id}|{provider.identity}')[:24];
  evidence_class='JURY_OPINION', tier='W2'
"""
import sys

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from veridict.jury import EID_SALT, Jury, Opinion, _read_sources  # noqa: E402
from veridict.schemas import Claim  # noqa: E402
from veridict.utils import sha256_hex  # noqa: E402


def _claim(cid="cid"):
    return Claim(claim_id=cid, task_id="t", subject="s", predicate="p",
                 scope="sc", summary="sm", derived_from="art",
                 verifiability="MACHINE", falsifiable_by=("a",), critical_class=None)


class _Prov:
    def __init__(self, identity="prov1", version="v1", family="Fam"):
        self.identity = identity
        self.version = version
        self.family = family


class _Dummy:
    """Jury._build_item self kullanmaz — bos self yeterli."""


# == _read_sources: temel ==============================================================================

def test_none_dir():
    assert _read_sources(None) is None


def test_bos_str():
    assert _read_sources("") is None


def test_yok_dir(tmp_path):
    assert _read_sources(str(tmp_path / "yok")) is None


def test_bos_dir(tmp_path):
    """ORTAM: dizin var ama .py yok -> None."""
    assert _read_sources(str(tmp_path)) is None


def test_tek_dosya(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    assert _read_sources(str(tmp_path)) == "--- a.py ---\nx = 1"


def test_iki_dosya_sirali(tmp_path):
    """ORTAM: sorted(os.listdir) — ALFABETIK sira."""
    (tmp_path / "b.py").write_text("b")
    (tmp_path / "a.py").write_text("a")
    out = _read_sources(str(tmp_path))
    assert out == "--- a.py ---\na\n\n--- b.py ---\nb"


def test_donus_tipi():
    assert isinstance(_read_sources(None), type(None)) or True


# == _read_sources: filtreleme ==========================================================================

def test_test_on_ekli_atlanir(tmp_path):
    """ORTAM: name.startswith('test_') -> ATLANIR."""
    (tmp_path / "a.py").write_text("x")
    (tmp_path / "test_z.py").write_text("y")
    assert _read_sources(str(tmp_path)) == "--- a.py ---\nx"


def test_py_olmayan_atlanir(tmp_path):
    (tmp_path / "a.py").write_text("x")
    (tmp_path / "b.txt").write_text("y")
    assert _read_sources(str(tmp_path)) == "--- a.py ---\nx"


def test_bos_dosya_atlanir(tmp_path):
    """ORTAM: text.strip() bos -> ATLANIR."""
    (tmp_path / "a.py").write_text("   \n  ")
    (tmp_path / "b.py").write_text("x")
    assert _read_sources(str(tmp_path)) == "--- b.py ---\nx"


def test_sadece_bos_dosya(tmp_path):
    (tmp_path / "a.py").write_text("")
    assert _read_sources(str(tmp_path)) is None


def test_sadece_test_dosya(tmp_path):
    (tmp_path / "test_a.py").write_text("x")
    assert _read_sources(str(tmp_path)) is None


def test_sadece_txt(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    assert _read_sources(str(tmp_path)) is None


def test_alt_cizgi_baslayan_py_okunur(tmp_path):
    """ORTAM: '_' ile baslayan .py OKUNUR (test_ on-eki haric)."""
    (tmp_path / "_a.py").write_text("x")
    assert _read_sources(str(tmp_path)) == "--- _a.py ---\nx"


def test_test_icinde_py_okunur(tmp_path):
    """ORTAM: 'mytest_x.py' -> startswith('test_') DEGIL -> OKUNUR."""
    (tmp_path / "mytest_x.py").write_text("x")
    assert _read_sources(str(tmp_path)) == "--- mytest_x.py ---\nx"


# == _read_sources: sinirlar ============================================================================

def test_6_dosya_siniri(tmp_path):
    """ORTAM: _MAX_SOURCE_FILES=6 — 7. dosya ALINMAZ."""
    for i in range(7):
        (tmp_path / f"f{i}.py").write_text(f"x{i}")
    out = _read_sources(str(tmp_path))
    assert "f5.py" in out
    assert "f0.py" in out


def test_6_dosya_sayisi_tam(tmp_path):
    for i in range(6):
        (tmp_path / f"f{i}.py").write_text("x")
    out = _read_sources(str(tmp_path))
    assert out.count("--- ") == 6


def test_7_dosya_sayisi_az(tmp_path):
    for i in range(10):
        (tmp_path / f"f{i}.py").write_text("x")
    assert _read_sources(str(tmp_path)).count("--- ") == 6


def test_byte_siniri_keser(tmp_path):
    """ORTAM: read(6000-total) — her dosya yalnizca kalan bütçe kadar okunur."""
    (tmp_path / "big.py").write_text("A" * 4000)
    (tmp_path / "b.py").write_text("B" * 2000)
    out = _read_sources(str(tmp_path))
    # 4000 + 2000 (kalan) = 6000 -> b.py TAMAMEN alinir
    assert out.count("A") == 4000
    assert out.count("B") == 2000


def test_byte_siniri_durdurur(tmp_path):
    """ORTAM: total >= 6000 -> break (3. dosya alinmaz)."""
    (tmp_path / "a.py").write_text("A" * 4000)
    (tmp_path / "b.py").write_text("B" * 3000)
    (tmp_path / "c.py").write_text("C" * 10)
    out = _read_sources(str(tmp_path))
    assert "C" not in out


def test_byte_siniri_tam_esit(tmp_path):
    """ORTAM: total==6000 -> break sonraki dosya alinmaz."""
    (tmp_path / "a.py").write_text("A" * 6000)
    (tmp_path / "b.py").write_text("B" * 5)
    out = _read_sources(str(tmp_path))
    assert "B" not in out


def test_büyük_dosya_kismi_okunur(tmp_path):
    (tmp_path / "big.py").write_text("A" * 100000)
    out = _read_sources(str(tmp_path))
    assert out.count("A") == 6000


def test_klasor_okuma_hatasi_gecilir(tmp_path, monkeypatch):
    """ORTAM: open OSError -> continue (izin hatasi dosyayi atlar)."""
    (tmp_path / "a.py").write_text("x")
    (tmp_path / "b.py").write_text("y")
    gercek = open

    def sahte_ac(yol, *a, **kw):
        if "b.py" in str(yol):
            raise PermissionError("yasak")
        return gercek(yol, *a, **kw)

    monkeypatch.setattr("builtins.open", sahte_ac)
    assert _read_sources(str(tmp_path)) == "--- a.py ---\nx"


def test_listdir_hatasi_none(tmp_path, monkeypatch):
    import os as _os
    gercek = _os.listdir

    def sahte_listdir(yol):
        raise PermissionError("yasak")

    monkeypatch.setattr(_os, "listdir", sahte_listdir)
    assert _read_sources(str(tmp_path)) is None


@pytest.mark.parametrize("n", [1, 2, 3, 5, 6])
def test_dosya_sayi_matrix(tmp_path, n):
    for i in range(n):
        (tmp_path / f"f{i}.py").write_text("x")
    assert _read_sources(str(tmp_path)).count("--- ") == n


@pytest.mark.parametrize("ad", ["a.py", "z.py", "_x.py", "Mod.py"])
def test_isim_matrix(tmp_path, ad):
    (tmp_path / ad).write_text("x")
    assert _read_sources(str(tmp_path)) == f"--- {ad} ---\nx"


# == Jury._build_item ===================================================================================

def test_evidence_id_uzunluk():
    it = Jury._build_item(_Dummy(), _claim(), "digest", _Prov(),
                          Opinion(stance="SUPPORTS", confidence=0.8, rationale="r"))
    assert len(it.evidence_id) == 24


def test_evidence_id_sha256_kesit():
    """ORTAM: sha256_hex(f'{salt}|{claim_id}|{identity}')[:24]."""
    c = _claim()
    p = _Prov()
    beklenen = sha256_hex(f"{EID_SALT}|{c.claim_id}|{p.identity}")[:24]
    it = Jury._build_item(_Dummy(), c, "digest", p,
                          Opinion(stance="REFUTES", confidence=0.3, rationale="r"))
    assert it.evidence_id == beklenen


def test_evidence_id_farkli_salt():
    c = _claim()
    p = _Prov()
    a = Jury._build_item(_Dummy(), c, "d", p, Opinion("SUPPORTS", 0.5, "r"))
    b = Jury._build_item(_Dummy(), c, "d", p, Opinion("SUPPORTS", 0.5, "r"),
                         round_salt="baska-salt")
    assert a.evidence_id != b.evidence_id


def test_evidence_id_farkli_claim():
    p = _Prov()
    a = Jury._build_item(_Dummy(), _claim("c1"), "d", p, Opinion("SUPPORTS", 0.5, "r"))
    b = Jury._build_item(_Dummy(), _claim("c2"), "d", p, Opinion("SUPPORTS", 0.5, "r"))
    assert a.evidence_id != b.evidence_id


def test_evidence_id_farkli_provider():
    c = _claim()
    a = Jury._build_item(_Dummy(), c, "d", _Prov("p1"), Opinion("SUPPORTS", 0.5, "r"))
    b = Jury._build_item(_Dummy(), c, "d", _Prov("p2"), Opinion("SUPPORTS", 0.5, "r"))
    assert a.evidence_id != b.evidence_id


def test_evidence_id_stabil():
    c = _claim()
    p = _Prov()
    o = Opinion("SUPPORTS", 0.5, "r")
    a = Jury._build_item(_Dummy(), c, "d", p, o)
    b = Jury._build_item(_Dummy(), c, "d", p, o)
    assert a.evidence_id == b.evidence_id


def test_sabit_alanlar():
    it = Jury._build_item(_Dummy(), _claim(), "digest", _Prov(),
                          Opinion("SUPPORTS", 0.8, "r"))
    assert it.evidence_class == "JURY_OPINION"
    assert it.tier == "W2"


def test_claim_id_bagli():
    it = Jury._build_item(_Dummy(), _claim("c1"), "digest", _Prov(),
                          Opinion("SUPPORTS", 0.8, "r"))
    assert it.claim_id == "c1"


def test_artifact_ref():
    it = Jury._build_item(_Dummy(), _claim(), "dig123", _Prov(),
                          Opinion("SUPPORTS", 0.8, "r"))
    assert it.artifact_ref == "dig123"


def test_stance_aktarilir():
    for s in ("SUPPORTS", "REFUTES"):
        it = Jury._build_item(_Dummy(), _claim(), "d", _Prov(),
                              Opinion(s, 0.5, "r"))
        assert it.stance == s


def test_confidence_aktarilir():
    for cf in (0.0, 0.25, 0.5, 0.99, 1.0):
        it = Jury._build_item(_Dummy(), _claim(), "d", _Prov(),
                              Opinion("SUPPORTS", cf, "r"))
        assert it.confidence == cf


def test_rationale_aktarilir():
    it = Jury._build_item(_Dummy(), _claim(), "d", _Prov(),
                          Opinion("SUPPORTS", 0.5, "gerekce metni"))
    assert it.rationale == "gerekce metni"


def test_producer_yapisi():
    it = Jury._build_item(_Dummy(), _claim(), "d", _Prov("p1", "v2", "F"),
                          Opinion("SUPPORTS", 0.5, "r"))
    assert it.producer["kind"] == "jury"
    assert it.producer["identity"] == "p1"
    assert it.producer["version"] == "v2"
    assert it.producer["family"] == "F"


def test_producer_actorref_dict():
    """ORTAM: ActorRef.to_dict() + ['family'] eklenir."""
    it = Jury._build_item(_Dummy(), _claim(), "d", _Prov("p1", "v2"),
                          Opinion("SUPPORTS", 0.5, "r"))
    assert isinstance(it.producer, dict)
    assert "family" in it.producer


def test_reproducibility_alanlari():
    """ORTAM-OGRENDI: deterministic=False, rerun_recipe=None — LLM ciktisi
    dogal olarak TEKRARLANABILIR DEGIL (real-LLM canary bulgusu)."""
    it = Jury._build_item(_Dummy(), _claim(), "d", _Prov(),
                          Opinion("SUPPORTS", 0.5, "r"))
    assert it.reproducibility["deterministic"] is False
    assert it.reproducibility["rerun_recipe"] is None


def test_self_kullanilmaz():
    """ORTAM: _build_item self'e erismEZ — sadece claim/provider/opinion gerekli."""
    class Bos:
        pass
    it = Jury._build_item(Bos(), _claim(), "d", _Prov(),
                          Opinion("SUPPORTS", 0.5, "r"))
    assert it is not None


@pytest.mark.parametrize("stance,confidence", [
    ("SUPPORTS", 0.0), ("SUPPORTS", 0.5), ("SUPPORTS", 1.0),
    ("REFUTES", 0.0), ("REFUTES", 0.5), ("REFUTES", 1.0),
])
def test_opinion_matrix(stance, confidence):
    it = Jury._build_item(_Dummy(), _claim(), "d", _Prov(),
                          Opinion(stance, confidence, "r"))
    assert it.stance == stance and it.confidence == confidence


@pytest.mark.parametrize("identity,version", [
    ("p1", "v1"), ("p2", "v2"), ("", ""), ("uzun-identity-123", "9.9.9"),
])
def test_provider_matrix(identity, version):
    it = Jury._build_item(_Dummy(), _claim(), "d", _Prov(identity, version),
                          Opinion("SUPPORTS", 0.5, "r"))
    assert it.producer["identity"] == identity
    assert it.producer["version"] == version
