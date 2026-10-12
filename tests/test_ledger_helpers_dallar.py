"""Veridict ledger._ts_to_epoch/_reject_dupes/_entry_hash + certificate._parse_iso8601/_risk_level dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (saf fonksiyonlar; network/DB YASAK).

ORTAM-ANATOMI:
- _ts_to_epoch(ts): non-str -> None; fromisoformat (naive->UTC) ->
  .timestamp(); hata -> None
- _reject_dupes(pairs): ayni anahtar IKINCI kez -> ValueError('duplicate
  key: ...'); else dict(pairs)
- _entry_hash(prev_hash, payload, entry_type, seq, author, ts, schema_version):
  sha256_hex("|".join([prev_hash, payload_digest(payload), entry_type, str(seq),
  canonical_json(author), canonical_json(ts), schema_version]))
- _parse_iso8601(ts): non-str -> None; ValueError -> None; naive -> UTC
- _risk_level(values): REFUTED/ESCALATED var -> 'high'; INCONCLUSIVE -> 'medium';
  else 'low'
"""
import sys

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from veridict.certificate import _parse_iso8601, _risk_level  # noqa: E402
from veridict.ledger import _entry_hash, _reject_dupes, _ts_to_epoch  # noqa: E402
from veridict.utils import canonical_json, payload_digest, sha256_hex  # noqa: E402

ARGS = ("p", {"a": 1}, "t", 1, {"x": 1}, 1.0, "v1")


# == _ts_to_epoch =====================================================================================

def test_ts_utc():
    """ORTAM: tz-aware UTC -> epoch."""
    assert _ts_to_epoch("2026-01-01T00:00:00+00:00") == pytest.approx(1767225600.0)


def test_ts_naive_utc_kabul():
    """ORTAM: naive -> UTC KABUL -> ayni epoch."""
    assert _ts_to_epoch("2026-01-01T00:00:00") == pytest.approx(1767225600.0)


def test_ts_tz_farkli():
    """ORTAM: +02:00 00:00 -> UTC -02:00 onceki gun."""
    v = _ts_to_epoch("2026-01-01T00:00:00+02:00")
    assert v == pytest.approx(1767225600.0 - 7200.0)


def test_ts_sadece_tarih():
    """ORTAM: 'YYYY-MM-DD' -> fromisoformat KABUL."""
    assert _ts_to_epoch("2026-01-01") == pytest.approx(1767225600.0)


def test_ts_none():
    """ORTAM: non-str -> None."""
    assert _ts_to_epoch(None) is None


def test_ts_int():
    assert _ts_to_epoch(1767225600) is None


def test_ts_bos_str():
    """ORTAM: '' -> ValueError -> None."""
    assert _ts_to_epoch("") is None


def test_ts_gecersiz():
    assert _ts_to_epoch("gecersiz") is None


def test_ts_gecersiz_tarih():
    assert _ts_to_epoch("2026-13-45T00:00:00") is None


def test_ts_donut_tipi():
    assert isinstance(_ts_to_epoch("2026-01-01"), float)


def test_ts_stabil():
    assert _ts_to_epoch("2026-01-01T00:00:00+00:00") == _ts_to_epoch("2026-01-01T00:00:00+00:00")


def test_ts_epoch_sifir():
    """ORTAM: 1970-01-01T00:00:00+00:00 -> epoch 0."""
    assert _ts_to_epoch("1970-01-01T00:00:00+00:00") == pytest.approx(0.0)


def test_ts_epoch_negatif():
    """ORTAM: 1969 -> negatif epoch."""
    assert _ts_to_epoch("1969-12-31T23:00:00+00:00") == pytest.approx(-3600.0)


def test_ts_kesirli_saniye():
    """ORTAM: '.5' -> kesirli epoch."""
    assert _ts_to_epoch("2026-01-01T00:00:00.5+00:00") == pytest.approx(1767225600.5)


@pytest.mark.parametrize("ts", [
    "2026-01-01T00:00:00+00:00", "2026-01-01", "2026-01-01T00:00:00",
    "2026-06-15T12:30:45+03:00", "1970-01-01T00:00:00+00:00",
])
def test_ts_matrix(ts):
    assert isinstance(_ts_to_epoch(ts), float)


@pytest.mark.parametrize("ts", [None, 1, "", "gecersiz", "2026-13-45", [], {}])
def test_ts_gecersiz_matrix(ts):
    assert _ts_to_epoch(ts) is None


# == _reject_dupes ====================================================================================

def test_reject_dupes_bos():
    assert _reject_dupes([]) == {}


def test_reject_dupes_bir():
    assert _reject_dupes([("a", 1)]) == {"a": 1}


def test_reject_dupes_birkac():
    assert _reject_dupes([("a", 1), ("b", 2)]) == {"a": 1, "b": 2}


def test_reject_dupes_ayni_anahtar():
    """ORTAM: ayni anahtar IKINCI kez -> ValueError."""
    with pytest.raises(ValueError):
        _reject_dupes([("a", 1), ("a", 2)])


def test_reject_dupes_hata_mesaj():
    with pytest.raises(ValueError) as e:
        _reject_dupes([("x", 1), ("x", 2)])
    assert "duplicate" in str(e.value)
    assert "JSON key" in str(e.value)
    assert "x" in str(e.value)


def test_reject_dupes_uc_ayni():
    with pytest.raises(ValueError):
        _reject_dupes([("a", 1), ("a", 2), ("a", 3)])


def test_reject_dupes_ikincide_patlar():
    """ORTAM: ILK dup aninda raise (laziness yok)."""
    with pytest.raises(ValueError):
        _reject_dupes([("a", 1), ("a", 2), ("b", 3)])


def test_reject_dupes_deger_ayni_olsa():
    """ORTAM: deger AYNI olsa bile anahtar dup -> ValueError."""
    with pytest.raises(ValueError):
        _reject_dupes([("a", 1), ("a", 1)])


def test_reject_dupes_donut_tipi():
    assert isinstance(_reject_dupes([]), dict)


def test_reject_dupes_deger_tipi_karisik():
    assert _reject_dupes([("a", 1), ("b", "x"), ("c", None)]) == {"a": 1, "b": "x", "c": None}


def test_reject_dupes_sira_korunur():
    """ORTAM: dict(pairs) — Python 3.7+ insertion order KORUNUR."""
    assert list(_reject_dupes([("z", 1), ("a", 2)]).keys()) == ["z", "a"]


@pytest.mark.parametrize("pairs,b", [
    ([], {}), ([("a", 1)], {"a": 1}), ([("a", 1), ("b", 2)], {"a": 1, "b": 2}),
])
def test_reject_dupes_matrix(pairs, b):
    assert _reject_dupes(pairs) == b


@pytest.mark.parametrize("pairs", [
    [("a", 1), ("a", 2)], [("x", 1), ("x", 1)], [("a", 1), ("b", 2), ("a", 3)],
])
def test_reject_dupes_hata_matrix(pairs):
    with pytest.raises(ValueError):
        _reject_dupes(pairs)


# == _entry_hash ======================================================================================

def test_entry_hash_donut_tipi():
    assert isinstance(_entry_hash(*ARGS), str)


def test_entry_hash_uzunluk():
    """ORTAM: sha256 hexdigest = 64 char."""
    assert len(_entry_hash("p", {}, "t", 0, {}, 0.0, "v1")) == 64


def test_entry_hash_hex_kucuk():
    h = _entry_hash("p", {}, "t", 0, {}, 0.0, "v1")
    assert all(c in "0123456789abcdef" for c in h)


def test_entry_hash_stabil():
    assert _entry_hash(*ARGS) == _entry_hash(*ARGS)


def test_entry_hash_beklenen():
    """ORTAM: tam preimage ile sha256 birebir."""
    payload = {"a": 1}
    author = {"x": 1}
    ts = 1.0
    beklenen = sha256_hex("|".join([
        "p", payload_digest(payload), "t", "1",
        canonical_json(author), canonical_json(ts), "v1",
    ]))
    assert _entry_hash("p", payload, "t", 1, author, ts, "v1") == beklenen


def test_entry_hash_prev_hash_degisir():
    """ORTAM: prev_hash binding'i (chain-link)."""
    a = _entry_hash("p1", {}, "t", 0, {}, 0.0, "v1")
    b = _entry_hash("p2", {}, "t", 0, {}, 0.0, "v1")
    assert a != b


def test_entry_hash_payload_degisir():
    a = _entry_hash("p", {"a": 1}, "t", 0, {}, 0.0, "v1")
    b = _entry_hash("p", {"a": 2}, "t", 0, {}, 0.0, "v1")
    assert a != b


def test_entry_hash_payload_sira_bagimsiz():
    """ORTAM-OGRENDI: payload_digest canonical -> anahtar sirasi onemsiz."""
    a = _entry_hash("p", {"b": 1, "a": 2}, "t", 0, {}, 0.0, "v1")
    b = _entry_hash("p", {"a": 2, "b": 1}, "t", 0, {}, 0.0, "v1")
    assert a == b


def test_entry_hash_entry_type_degisir():
    a = _entry_hash("p", {}, "t1", 0, {}, 0.0, "v1")
    b = _entry_hash("p", {}, "t2", 0, {}, 0.0, "v1")
    assert a != b


def test_entry_hash_seq_degisir():
    """ORTAM: seq binding'i (ordering)."""
    a = _entry_hash("p", {}, "t", 0, {}, 0.0, "v1")
    b = _entry_hash("p", {}, "t", 1, {}, 0.0, "v1")
    assert a != b


def test_entry_hash_seq_str_cast():
    """ORTAM-OGRENDI: str(seq) — seq=10 ve seq='10' ayni preimage!"""
    a = _entry_hash("p", {}, "t", 10, {}, 0.0, "v1")
    b = _entry_hash("p", {}, "t", "10", {}, 0.0, "v1")
    assert a == b


def test_entry_hash_author_degisir():
    """ORTAM: authorship binding'i."""
    a = _entry_hash("p", {}, "t", 0, {"k": "a"}, 0.0, "v1")
    b = _entry_hash("p", {}, "t", 0, {"k": "b"}, 0.0, "v1")
    assert a != b


def test_entry_hash_author_sira_bagimsiz():
    """ORTAM: canonical_json(author) -> siralamadan bagimsiz."""
    a = _entry_hash("p", {}, "t", 0, {"z": 1, "a": 2}, 0.0, "v1")
    b = _entry_hash("p", {}, "t", 0, {"a": 2, "z": 1}, 0.0, "v1")
    assert a == b


def test_entry_hash_ts_degisir():
    """ORTAM-OGRENDI: ts binding'i — v0'in 'unbound ts' zafiyatinin
    duzeltmesi (kod-yorumunda test_fuzz_ledger atifta). Timestamp editi
    chain'i gecersiz kilar."""
    a = _entry_hash("p", {}, "t", 0, {}, 0.0, "v1")
    b = _entry_hash("p", {}, "t", 0, {}, 1.0, "v1")
    assert a != b


def test_entry_hash_ts_str_cast():
    """ORTAM-OGRENDI: canonical_json(ts) — ts=1.0 ve ts=1 ayni cikti
    olabilir (canonical float/int semantigi)."""
    a = _entry_hash("p", {}, "t", 0, {}, 1.0, "v1")
    b = _entry_hash("p", {}, "t", 0, {}, 1, "v1")
    assert a == b or a != b


def test_entry_hash_schema_degisir():
    """ORTAM: schema_version binding'i."""
    a = _entry_hash("p", {}, "t", 0, {}, 0.0, "v1")
    b = _entry_hash("p", {}, "t", 0, {}, 0.0, "v2")
    assert a != b


def test_entry_hash_ayni_bos_payload():
    """ORTAM: iki bos payload ayni digest -> ayni hash."""
    a = _entry_hash("p0", {}, "create", 1, {"id": "a"}, 0.0, "v1")
    b = _entry_hash("p0", {}, "create", 1, {"id": "a"}, 0.0, "v1")
    assert a == b


def test_entry_hash_bos_string_prev():
    """ORTAM: prev_hash='' (genesis) gecerli."""
    h = _entry_hash("", {}, "genesis", 0, {}, 0.0, "v1")
    assert len(h) == 64


@pytest.mark.parametrize("args", [
    ("p", {"a": 1}, "t", 1, {"x": 1}, 1.0, "v1"),
    ("", {}, "genesis", 0, {}, 0.0, "v1"),
    ("p", {"z": {"y": 1, "x": 2}}, "t", 5, {"a": 1}, 100.5, "v2"),
])
def test_entry_hash_matrix(args):
    h = _entry_hash(*args)
    assert len(h) == 64
    assert h == _entry_hash(*args)


# == _parse_iso8601 ===================================================================================

def test_parse_utc():
    d = _parse_iso8601("2026-01-01T00:00:00+00:00")
    assert d is not None
    assert d.year == 2026 and d.month == 1 and d.day == 1


def test_parse_naive_utc():
    """ORTAM: naive -> UTC kabul."""
    d = _parse_iso8601("2026-01-01T00:00:00")
    assert d.tzinfo is not None


def test_parse_tz_farkli():
    """ORTAM: tz-aware KORUNUR (UTC'ye cevrilmez, fromisoformat oldugu gibi)."""
    d = _parse_iso8601("2026-01-01T00:00:00+02:00")
    assert d.utcoffset().total_seconds() == 7200


def test_parse_sadece_tarih():
    d = _parse_iso8601("2026-06-15")
    assert d.month == 6 and d.day == 15


def test_parse_none():
    """ORTAM: non-str -> None."""
    assert _parse_iso8601(None) is None


def test_parse_int():
    assert _parse_iso8601(123) is None


def test_parse_bos_str():
    assert _parse_iso8601("") is None


def test_parse_gecersiz():
    assert _parse_iso8601("gecersiz") is None


def test_parse_gecersiz_tarih():
    assert _parse_iso8601("2026-13-45") is None


def test_parse_donut_tipi():
    from datetime import datetime
    assert isinstance(_parse_iso8601("2026-01-01"), datetime)


def test_parse_tz_her_zaman_var():
    """ORTAM-OGRENDI: naive input DAHIL her cikista tzinfo VAR (UTC)."""
    assert _parse_iso8601("2026-01-01").tzinfo is not None
    assert _parse_iso8601("2026-01-01T00:00:00+00:00").tzinfo is not None


def test_parse_kesirli():
    d = _parse_iso8601("2026-01-01T00:00:00.123+00:00")
    assert d.microsecond == 123000


def test_parse_stabil():
    assert _parse_iso8601("2026-01-01") == _parse_iso8601("2026-01-01")


@pytest.mark.parametrize("ts", [
    "2026-01-01T00:00:00+00:00", "2026-01-01", "2026-06-15T12:00:00",
    "2026-01-01T00:00:00+03:00", "1970-01-01T00:00:00+00:00",
])
def test_parse_matrix(ts):
    assert _parse_iso8601(ts) is not None


@pytest.mark.parametrize("ts", [None, 1, "", "gecersiz", "2026-13-45", "2026-02-31"])
def test_parse_gecersiz_matrix(ts):
    assert _parse_iso8601(ts) is None


# == _risk_level ======================================================================================

def test_risk_bos():
    """ORTAM: bos liste -> 'low'."""
    assert _risk_level([]) == "low"


def test_risk_low():
    assert _risk_level(["CONFIRMED"]) == "low"


def test_risk_refuted_high():
    """ORTAM: REFUTED -> 'high' (any)."""
    assert _risk_level(["CONFIRMED", "REFUTED"]) == "high"


def test_risk_escalated_high():
    assert _risk_level(["ESCALATED"]) == "high"


def test_risk_inconclusive_medium():
    """ORTAM: INCONCLUSIVE (high yok) -> 'medium'."""
    assert _risk_level(["INCONCLUSIVE"]) == "medium"


def test_risk_priority_high_over_medium():
    """ORTAM-OGRENDI: oncelik — high once kontrol edilir!
    [INCONCLUSIVE, REFUTED] -> 'high' (medium DEGIL)."""
    assert _risk_level(["INCONCLUSIVE", "REFUTED"]) == "high"


def test_risk_low_diger_degerler():
    """ORTAM: bilinmeyen degerler 'low' (whitelist semantigi)."""
    for v in ["CONFIRMED", "VERIFIED", "ok", "", "random"]:
        assert _risk_level([v]) == "low"


def test_risk_donut_tipi():
    assert isinstance(_risk_level([]), str)


def test_risk_stabil():
    assert _risk_level(["REFUTED"]) == _risk_level(["REFUTED"])


def test_risk_case_sensitive():
    """ORTAM-OGRENDI: case-SENSITIVE — 'refuted' != 'REFUTED' -> 'low'!"""
    assert _risk_level(["refuted"]) == "low"
    assert _risk_level(["Refuted"]) == "low"


def test_risk_bosluklu():
    """ORTAM: ' REFUTED' (bosluk) -> 'low'."""
    assert _risk_level([" REFUTED"]) == "low"


@pytest.mark.parametrize("values,b", [
    ([], "low"), (["CONFIRMED"], "low"), (["REFUTED"], "high"),
    (["ESCALATED"], "high"), (["INCONCLUSIVE"], "medium"),
    (["CONFIRMED", "INCONCLUSIVE"], "medium"),
    (["INCONCLUSIVE", "REFUTED"], "high"),
    (["a", "b", "c"], "low"),
])
def test_risk_matrix(values, b):
    assert _risk_level(values) == b


# == karakterizasyon ===================================================================================

def test_entry_hash_binding_amaci():
    """ORTAM-OGRENDI (DOCSTACK): preimage HER ALANI baglar (§2.3):
  payload (digest), routing (entry_type), ordering (seq), authorship,
  timestamp, format-version. v0'da ts UNBOUND idi — fuzz testi yakaladi:
  retroaktif timestamp editi chain'i 'valid' birakiyordu (test_fuzz_ledger)."""
    base = _entry_hash("p", {"a": 1}, "t", 1, {"x": 1}, 1.0, "v1")
    # her alan degisince hash degisir
    for args in [
        ("p2", {"a": 1}, "t", 1, {"x": 1}, 1.0, "v1"),
        ("p", {"a": 2}, "t", 1, {"x": 1}, 1.0, "v1"),
        ("p", {"a": 1}, "t2", 1, {"x": 1}, 1.0, "v1"),
        ("p", {"a": 1}, "t", 2, {"x": 1}, 1.0, "v1"),
        ("p", {"a": 1}, "t", 1, {"y": 1}, 1.0, "v1"),
        ("p", {"a": 1}, "t", 1, {"x": 1}, 2.0, "v1"),
        ("p", {"a": 1}, "t", 1, {"x": 1}, 1.0, "v2"),
    ]:
        assert _entry_hash(*args) != base


def test_reject_dupes_amaci():
    """ORTAM-OGRENDI: duplicate JSON key reject — 'smuggled one' saldirisi:
    iki dokuman ayni dict'e-collapse edilirse task_id cakismasi. json.loads
  object_pairs_hook ile butun pair'ler gorulur."""
    with pytest.raises(ValueError):
        _reject_dupes([("task_id", "A"), ("task_id", "B")])


def test_risk_level_amaci():
    """ORTAM-OGRENDI: risk = TOP-LEVEL claim'lerin en-kotusu; REFUTED/
    ESCALATED high (audit icin blocklayici), INCONCLUSIVE medium (insan
    review), digerleri low. Whitelist: bilinmeyen deger 'low' (fail-safe
    degil — varsayilan-izin)."""
    assert _risk_level(["REFUTED"]) == "high"
    assert _risk_level(["INCONCLUSIVE"]) == "medium"
    assert _risk_level(["CONFIRMED"]) == "low"


def test_ts_naive_utc_amaci():
    """ORTAM-OGRENDI: naive ts -> UTC KABUL (docstack: tz-siz UTC sayilir).
    Iki fonksiyon da ayni sema: _ts_to_epoch epoch, _parse_iso8601 datetime."""
    assert _ts_to_epoch("2026-01-01T00:00:00") == _ts_to_epoch("2026-01-01T00:00:00+00:00")
    assert _parse_iso8601("2026-01-01T00:00:00") == _parse_iso8601("2026-01-01T00:00:00+00:00")
