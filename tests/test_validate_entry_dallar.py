"""Veridict ledger.Ledger._validate_entry dal-kesen testleri (LEED).

Kural-1: MEVCUT DOSYALARA DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (Ledger bellek-ornekleri — dosya/YAZMA dis cagri YOK).
_validate_entry: append-only zincirin okuyucu-tarafi sekil-kontrolu —
seq konum-tokeni (D20 replay-korumasi), tip-karistirma (str(0)=='0' daha
once ayni-hash), bool int-alt-sinifi celiskisi.
"""
import sys

import pytest

sys.path.insert(0, ".")
from veridict.ledger import Ledger  # noqa: E402
from veridict.schemas import ActorRef  # noqa: E402

_REQUIRED = ("schema_version", "seq", "prev_hash", "entry_type", "author",
             "payload", "ts", "payload_hash", "entry_hash")
_STR_KEYS = ("schema_version", "entry_type", "prev_hash", "payload_hash",
             "entry_hash")


def _valid_entry() -> dict:
    """Tam gecerli giris (bellek icinde uretilir — dosya YAZILMAZ)."""
    led = Ledger()
    return led.append("test.t", ActorRef(kind="system", identity="i",
                                         version="1"), {"k": "v"})


# == gecerli giris ==============================================================================

@pytest.mark.parametrize("lineno", [0, 1, 2, 100, 99999, -1])
def test_gecerli_giris_kabul(lineno):
    """ORTAM: tam giris her (hatta negatif/sifir) lineno icin None doner —
    hata FIRLATMAZ, sessiz-basarir."""
    assert Ledger._validate_entry(_valid_entry(), lineno) is None


def test_statik_metot_erisimi():
    """ORTAM: @staticmethod — sinif uzerinden de ornek uzerinden de cagrilir."""
    e = _valid_entry()
    assert Ledger._validate_entry(e, 1) is None
    assert Ledger()._validate_entry(e, 1) is None


def test_giris_referans_dokunulmaz():
    """ORTAM: gecerli giris MUTASYONA UGRAMAZ (kontrol yan-etkisiz)."""
    e = _valid_entry()
    before = dict(e)
    Ledger._validate_entry(e, 1)
    assert e == before


# == entry dict-degil ============================================================================

@pytest.mark.parametrize("bad", ["str", [1, 2], None, 5, 1.5, ("a",), {1}])
def test_entry_dict_degil(bad):
    """ORTAM: entry bir dict DEGILSE -> ChainError ('entry is not an object').
    JSON-satiri olmayan her sey reddedilir — fail-closed okuyucu."""
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(bad, 1)
    assert "not an object" in str(ei.value)


# == eksik anahtarlar ============================================================================

@pytest.mark.parametrize("key", _REQUIRED)
def test_eksik_anahtar(key):
    """ORTAM: 9-zorunlu anahtardan herhangibirinin EKSIK -> ChainError
    'missing required keys' + SIRALI-liste."""
    e = _valid_entry()
    del e[key]
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(e, 1)
    assert "missing required keys" in str(ei.value)
    assert key in str(ei.value)


def test_eksik_anahtar_mesaji_sirali():
    """ORTAM-OGRENDI: hata mesaji sorted(missing) — coklu-eksiklikte
    deterministik-sira (hata-mesaji test-edilebilir)."""
    e = _valid_entry()
    del e["entry_hash"]
    del e["author"]
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(e, 1)
    msg = str(ei.value)
    # sorted: author once entry_hash'ten
    assert msg.index("author") < msg.index("entry_hash")


def test_coklu_eksik_anahtar():
    """ORTAM: birden fazla eksik anahtar hepsi listelenir."""
    e = _valid_entry()
    del e["ts"]
    del e["seq"]
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(e, 1)
    assert "seq" in str(ei.value)
    assert "ts" in str(ei.value)


def test_fazla_anahtar_kabul():
    """ORTAM: _REQUIRED disinda fazla anahtarlar KABUL edilir (uzanti-alani)."""
    e = _valid_entry()
    e["extra_field"] = "ok"
    assert Ledger._validate_entry(e, 1) is None


# == seq: konum-tokeni (D20) =====================================================================

@pytest.mark.parametrize("bad_seq", [
    True,           # bool int-alt-sinifi: True == 1 ile CELISIR
    "0",            # str: str(0)=='0' ayni-hash tip-karistirma
    1.0,            # float
    None,
    [0],
    {0},
    0.0,
    (0,),
])
def test_seq_tipi_reddi(bad_seq):
    """ORTAM-OGRENDI: seq SADECE int (bool HARIC) — bool int-alt-sinifi
    oldugu icin True/False ayrica reddedilir (True == 1 sessiz-cakismasi).
    str(0)=='0' once ayni-entry-hash uretir, sonra audit-yolu TypeError. D20:
    seq KONUM-tokenidir, pozisyonla esit olmali (replay-korumasi)."""
    e = _valid_entry()
    e["seq"] = bad_seq
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(e, 1)
    assert "seq is not an integer" in str(ei.value)


@pytest.mark.parametrize("seq", [0, 1, -1, 42, 999999, -999999])
def test_seq_gecerli_int_kabul(seq):
    """ORTAM: her int (negatif DAHIL) kabul — kontrol TIPE bakar, DEGERE
    DEGIL (deger-kontrolu verify_chain'in isidir, D20 scope)."""
    e = _valid_entry()
    e["seq"] = seq
    assert Ledger._validate_entry(e, 1) is None


def test_seq_bool_true_red_msg():
    """ORTAM: True ozellikle reddedilir — bool int-alt-sinifi kontrolu once."""
    e = _valid_entry()
    e["seq"] = True
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(e, 1)
    assert "seq is not an integer" in str(ei.value)


# == payload / author / ts =======================================================================

@pytest.mark.parametrize("bad", [[], "str", None, 5, 1.5, [1, 2]])
def test_payload_dict_degil(bad):
    """ORTAM: payload bir dict DEGILSE -> ChainError (payload_hash hesaplanamaz)."""
    e = _valid_entry()
    e["payload"] = bad
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(e, 1)
    assert "payload is not an object" in str(ei.value)


@pytest.mark.parametrize("good", [{}, {"k": "v"}, {"a": {"b": [1]}}])
def test_payload_gecerli_dict(good):
    """ORTAM: her dict (bos DAHIL) kabul — icerik kontrolu yapilmaz."""
    e = _valid_entry()
    e["payload"] = good
    assert Ledger._validate_entry(e, 1) is None


@pytest.mark.parametrize("bad", [[], "str", None, 5, 1.5, (1, 2)])
def test_author_dict_degil(bad):
    """ORTAM: author dict DEGILSE -> ChainError (ActorRef.to_dict cikti)."""
    e = _valid_entry()
    e["author"] = bad
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(e, 1)
    assert "author is not an object" in str(ei.value)


@pytest.mark.parametrize("good", [{}, {"kind": "system"}, {"a": {"b": [1]}}])
def test_author_gecerli_dict(good):
    """ORTAM: author dict oldugunda kabul — icerik-kontrolu YOK (sadece tip)."""
    e = _valid_entry()
    e["author"] = good
    assert Ledger._validate_entry(e, 1) is None


@pytest.mark.parametrize("bad", [123, None, [], 1.5, {"k": "v"}, (1,)])
def test_ts_str_degil(bad):
    """ORTAM: ts SADECE str — ISO-8601 timestamp; float-ts hash-pozisyonunda
    dil-kirilgan (§2.3), bu yuzden tip-erken reddedilir."""
    e = _valid_entry()
    e["ts"] = bad
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(e, 1)
    assert "ts is not a string" in str(ei.value)


@pytest.mark.parametrize("good", ["", "2023-01-01T00:00:00Z", "garbage", "x"])
def test_ts_gecerli_str(good):
    """ORTAM: her str kabul — PARSE kontrolu yapilmaz (bu fonksiyon
    sekil-kontroludur; ts-cozumleme verify_chain'in isidir)."""
    e = _valid_entry()
    e["ts"] = good
    assert Ledger._validate_entry(e, 1) is None


# == string anahtarlar ===========================================================================

@pytest.mark.parametrize("key", _STR_KEYS)
@pytest.mark.parametrize("bad", [123, None, [], 1.5, {"k": "v"}, True])
def test_str_anahtar_tip_reddi(key, bad):
    """ORTAM: 5-string-alanin her biri str DISI tip -> ChainError
    '<key> is not a string' (hash girdisi string-kanonik)."""
    e = _valid_entry()
    e[key] = bad
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(e, 1)
    assert f"{key} is not a string" in str(ei.value)


@pytest.mark.parametrize("key", _STR_KEYS)
def test_str_anahtar_bos_str_kabul(key):
    """ORTAM: bos-str gecerli — deger-icerigi kontrolu YOK (bos hash'ler
    GENESIS/ilk-giris icin normal)."""
    e = _valid_entry()
    e[key] = ""
    assert Ledger._validate_entry(e, 1) is None


# == hata tipi ====================================================================================

def test_hata_turu_chain_error():
    """ORTAM: butun reddedmeler ChainError — ledgere ozel istisna
    (json.JSONDecodeError DEGIL, ValueError DEGIL)."""
    from veridict.ledger import ChainError
    e = _valid_entry()
    del e["seq"]
    with pytest.raises(ChainError):
        Ledger._validate_entry(e, 1)


def test_hata_mesaji_lineno_icerir():
    """ORTAM: hata mesaji her yolda lineno icerir (denetim-izleme)."""
    e = _valid_entry()
    del e["ts"]
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry(e, 42)
    assert "42" in str(ei.value)


def test_lineno_mesajda_gorunur_nonobj():
    """ORTAM: dict-degil yolunda da lineno mesajda."""
    with pytest.raises(Exception) as ei:
        Ledger._validate_entry("not-dict", 7)
    assert "7" in str(ei.value)


# == uretim-tutarlilik ===========================================================================

def test_append_girisi_daima_gecerli():
    """ORTAM: Ledger.append() ciktisi _validate_entry'i GECER —
    uretici-sozlesme (invariant) okuyucu tarafindan test edilir."""
    led = Ledger()
    for i in range(5):
        e = led.append(f"type.{i}", ActorRef(kind="system", identity="i",
                                             version="1"), {"i": i})
        assert Ledger._validate_entry(e, i + 1) is None


def test_butun_zorunlu_anahtarlar_kumesi():
    """ORTAM-ANATOMI: 9-zorunlu-anahtar sabit-kume, ekstra alanlar serbest."""
    e = _valid_entry()
    assert set(_REQUIRED) <= set(e)
