"""Veridict ledger/certificate/dossier dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (datetime/sha256 — dis cagri YOK).
_ts_to_epoch + _entry_hash + _parse_iso8601 + _risk_level + _dedupe.
"""
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, ".")
from veridict.ledger import _ts_to_epoch, _entry_hash  # noqa: E402
from veridict.certificate import _parse_iso8601, _risk_level  # noqa: E402
from veridict.dossier import _dedupe  # noqa: E402


# == _ts_to_epoch =================================================================================

def test_zulu():
    """ORTAM: 'Z' -> 'tz utc'."""
    assert _ts_to_epoch("2023-01-01T00:00:00Z") == 1672531200.0


def test_offset():
    assert _ts_to_epoch("2023-01-01T02:00:00+02:00") == 1672531200.0


def test_naive_utc_varsayilan():
    """ORTAM: tzinfo yoksa UTC varsayilir."""
    assert _ts_to_epoch("2023-01-01T00:00:00") == 1672531200.0


def test_tarih_only():
    """ORTAM: 'T' yoksa da parse."""
    assert _ts_to_epoch("2023-01-01") is not None


def test_bos_str():
    assert _ts_to_epoch("") is None


def test_int_input():
    """ORTAM: str DEGIL -> None."""
    assert _ts_to_epoch(12345) is None


def test_none_input():
    assert _ts_to_epoch(None) is None


def test_list_input():
    assert _ts_to_epoch([]) is None


def test_bool_input():
    assert _ts_to_epoch(True) is None


def test_gecersiz_str():
    assert _ts_to_epoch("gecersiz") is None


def test_gecersiz_tarih():
    assert _ts_to_epoch("2023-13-45T99:99:99Z") is None


def test_returns_float():
    assert isinstance(_ts_to_epoch("2023-01-01T00:00:00Z"), float)


def test_microseconds():
    r = _ts_to_epoch("2023-01-01T00:00:00.500000Z")
    assert r == 1672531200.5


def test_saniye_kesir():
    assert _ts_to_epoch("2023-01-01T00:00:01Z") == 1672531201.0


def test_negatif_offset():
    assert _ts_to_epoch("2023-01-01T00:00:00-02:00") == 1672538400.0


def test_positif_offset():
    assert _ts_to_epoch("2023-01-01T00:00:00+05:30") == 1672511400.0


def test_repeatable():
    assert _ts_to_epoch("2023-01-01T00:00:00Z") == \
        _ts_to_epoch("2023-01-01T00:00:00Z")


@pytest.mark.parametrize("ts", ["2023-01-01T00:00:00Z",
                                "2023-06-15T12:30:45Z",
                                "2020-02-29T23:59:59Z"])
def test_gecerli_matrix(ts):
    assert _ts_to_epoch(ts) is not None


@pytest.mark.parametrize("bad", [None, 1, [], {}, True, "x", "", "2023"])
def test_gecersiz_matrix(bad):
    assert _ts_to_epoch(bad) is None


# == _parse_iso8601 ================================================================================

def test_parse_zulu():
    d = _parse_iso8601("2023-01-01T00:00:00Z")
    assert d == datetime(2023, 1, 1, tzinfo=timezone.utc)


def test_parse_tz_varsayilan():
    """ORTAM: tzinfo yoksa UTC."""
    d = _parse_iso8601("2023-01-01T00:00:00")
    assert d.tzinfo == timezone.utc


def test_parse_returns_datetime():
    assert isinstance(_parse_iso8601("2023-01-01T00:00:00Z"), datetime)


def test_parse_none():
    assert _parse_iso8601(None) is None


def test_parse_int():
    assert _parse_iso8601(5) is None


def test_parse_gecersiz():
    assert _parse_iso8601("gecersiz") is None


def test_parse_bos():
    assert _parse_iso8601("") is None


def test_parse_offset_korunur():
    """ORTAM: offset varsa KORUNUR (UTC'ye donusum YOK)."""
    d = _parse_iso8601("2023-01-01T02:00:00+02:00")
    assert d.utcoffset().total_seconds() == 7200


def test_parse_micro():
    d = _parse_iso8601("2023-01-01T00:00:00.5Z")
    assert d.microsecond == 500000


def test_parse_tarih_only():
    d = _parse_iso8601("2023-06-15")
    assert d.month == 6 and d.day == 15


# == _risk_level ===================================================================================

def test_refuted_high():
    assert _risk_level(["REFUTED"]) == "high"


def test_escalated_high():
    assert _risk_level(["ESCALATED"]) == "high"


def test_refuted_sirali_oncelik():
    """ORTAM: high once kontrol edilir."""
    assert _risk_level(["INCONCLUSIVE", "REFUTED"]) == "high"


def test_inconclusive_medium():
    assert _risk_level(["INCONCLUSIVE"]) == "medium"


def test_bos_low():
    assert _risk_level([]) == "low"


def test_diger_low():
    assert _risk_level(["SUPPORTED", "UPHELD"]) == "low"


def test_bos_str_low():
    assert _risk_level([""]) == "low"


def test_returns_str():
    assert isinstance(_risk_level([]), str)


def test_case_sensitive():
    """ORTAM: buyuk-harf gerekir."""
    assert _risk_level(["refuted"]) == "low"


def test_repeatable():
    assert _risk_level(["REFUTED"]) == _risk_level(["REFUTED"])


@pytest.mark.parametrize("vals,exp", [
    (["REFUTED"], "high"),
    (["ESCALATED"], "high"),
    (["INCONCLUSIVE"], "medium"),
    (["SUPPORTED"], "low"),
    ([], "low"),
    (["A", "REFUTED", "B"], "high"),
    (["A", "INCONCLUSIVE", "B"], "medium"),
])
def test_risk_matrix(vals, exp):
    assert _risk_level(vals) == exp


# == _dedupe =======================================================================================

def test_bos():
    assert _dedupe([]) == []


def test_tek():
    assert _dedupe(["a"]) == ["a"]


def test_tekrar_kaldirilir():
    assert _dedupe(["a", "a", "a"]) == ["a"]


def test_sira_korunur():
    """ORTAM: ILK-gorunum sirasi korunur."""
    assert _dedupe(["c", "a", "b", "a", "c"]) == ["c", "a", "b"]


def test_hepsi_farkli():
    assert _dedupe(["a", "b", "c"]) == ["a", "b", "c"]


def test_returns_list():
    assert isinstance(_dedupe([]), list)


def test_repeatable():
    assert _dedupe(["a", "a"]) == _dedupe(["a", "a"])


def test_turkce():
    assert _dedupe(["Türkçe", "Türkçe", "x"]) == ["Türkçe", "x"]


def test_emoji():
    assert _dedupe(["🤖", "🤖"]) == ["🤖"]


def test_bos_str():
    assert _dedupe(["", ""]) == [""]


def test_karisik_tipli_str():
    """ORTAM: tum elemanlar str."""
    assert _dedupe(["1", "1", "2"]) == ["1", "2"]


@pytest.mark.parametrize("items,exp", [
    ([], []), (["a"], ["a"]), (["a", "a"], ["a"]),
    (["b", "a", "b"], ["b", "a"]), (["x", "x", "x"], ["x"]),
])
def test_dedupe_matrix(items, exp):
    assert _dedupe(items) == exp


# == _entry_hash ===================================================================================

def _eh(**kw):
    """7-parametreli _entry_hash wrapper (keyword-only)."""
    from veridict.ledger import _entry_hash as _h
    d = {"prev_hash": "p", "payload": {}, "entry_type": "e",
         "seq": 0, "author": {}, "ts": 0.0, "schema_version": "v1"}
    d.update(kw)
    return _h(**d)


def test_entry_hash_str():
    """ORTAM: sha256-hex (64-char) — 7-parametreli."""
    r = _eh()
    assert isinstance(r, str) and len(r) == 64


def test_entry_hash_deterministik():
    h1 = _eh(payload={"a": 1}, author={"n": "x"}, ts=1.0)
    h2 = _eh(payload={"a": 1}, author={"n": "x"}, ts=1.0)
    assert h1 == h2


def test_entry_hash_prev_farkli():
    assert _eh(prev_hash="p1") != _eh(prev_hash="p2")


def test_entry_hash_payload_farkli():
    assert _eh(payload={"a": 1}) != _eh(payload={"a": 2})


def test_entry_hash_ts_farkli():
    assert _eh(ts=1.0) != _eh(ts=2.0)


def test_entry_hash_hex():
    assert all(c in "0123456789abcdef" for c in _eh())


def test_entry_hash_bos_input():
    assert isinstance(_eh(prev_hash="", payload={}), str)


def test_entry_hash_entry_type_farkli():
    assert _eh(entry_type="a") != _eh(entry_type="b")


def test_entry_hash_seq_farkli():
    assert _eh(seq=0) != _eh(seq=1)


def test_entry_hash_schema_farkli():
    assert _eh(schema_version="v1") != _eh(schema_version="v2")


def test_entry_hash_author_farkli():
    assert _eh(author={"a": 1}) != _eh(author={"b": 2})
