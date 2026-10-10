# -*- coding: utf-8 -*-
"""Dal-kesen (branch-cutting) unit testler — ``veridict.certificate._risk_level_for``.

Hedef: ``Veridict/veridict/certificate.py:47`` module-level ``_risk_level_for``
(19 satır). Sertifikaların risk-düzeyini, SADECE üst-seviye (artifact-hakkındaki)
iddialardan-çıkaran fonksiyonun TÜM dalları kesilir:

  F1  filtre: c.verifiability != "DOCTRINAL"  OR  not predicate.startswith("coverage-of-")
      → 4 kombinasyon-dalı (DOCTRINAL×coverage dışlanır; diğer-3'i dahil)
  F2  önek-sınırı: "coverage-of" (tire-yok) dışlanMAZ
  V1  per_claim[dict]  → a["value"]
  V2  per_claim[nesne] → a.value  (Adjudication)
  R1  _risk_level: REFUTED|ESCALATED → high
  R2  _risk_level: INCONCLUSIVE       → medium
  R3  _risk_level: diğer              → low
  R4  öncelik: REFUTED > INCONCLUSIVE (sıra-duyarsız)
  S1  boş-iddia / hepsi-dışlanan → values=[] → low
  S2  KeyError/AttributeError üretim-sınırları

Disiplin (görev-kuralları):
  • SADECE YENİ DOSYA — production'a DOKUNULMADI.
  • Saf in-memory; dış ağ/HTTP/DB/ledger çağrısı YOK.
  • MOCK YOK — gerçek Claim/Adjudication veri-sınıflarıyla.
"""

import pytest

from veridict.certificate import _risk_level, _risk_level_for
from veridict.ladder import Adjudication
from veridict.schemas import Claim


def _claim(cid, verifiability="MACHINE_CHECKABLE", predicate="is-faster",
           status="OPEN"):
    """Test-iddiası-üreteci (gerçek Claim; stub YOK)."""
    return Claim(claim_id=cid, task_id="task-1", subject="artifact.tar",
                 predicate=predicate, scope="full", summary="s",
                 derived_from="sha256:abc", verifiability=verifiability,
                 falsifiable_by=(), critical_class=None, status=status)


# ───────────── F1: filtre — DOCTRINAL + coverage-of-* DIŞLANIR ─────────────
@pytest.mark.parametrize("predicate", ["coverage-of-perf", "coverage-of-security",
                                       "coverage-of-x"])
def test_doctrinal_coverage_meta_claim_excluded(predicate):
    """F1: DOCTRINAL & coverage-of-* meta-iddiası dışlanır — değeri REFUTED
    olsa-bile risk-yükselMEZ (doktrin-büyüme-koruması)."""
    claims = [_claim("c1", "DOCTRINAL", predicate)]
    assert _risk_level_for(claims, {"c1": {"value": "REFUTED"}}) == "low"


@pytest.mark.parametrize("predicate", ["is-faster", "is-secure", "coverage-summary"])
def test_doctrinal_non_coverage_claim_included(predicate):
    """F1: DOCTRINAL-AMA coverage-of-* DEĞİL → dahil; değeri-hesaba-katılır."""
    claims = [_claim("c1", "DOCTRINAL", predicate)]
    assert _risk_level_for(claims, {"c1": {"value": "INCONCLUSIVE"}}) == "medium"


@pytest.mark.parametrize("verifiability", ["MACHINE_CHECKABLE", "MIXED"])
def test_coverage_predicate_only_excluded_when_doctrinal(verifiability):
    """F1: coverage-of-* öneki SADECE DOCTRINAL-ise-dışlar; MACHINE_CHECKABLE
    ve MIXED iddialar DAHİL-edilir ve risklerini-yansıştırır."""
    claims = [_claim("c1", verifiability, "coverage-of-perf")]
    assert _risk_level_for(claims, {"c1": {"value": "REFUTED"}}) == "high"


# ───────────────────── F2: önek-sınırı (startswith kesimi) ─────────────────────
@pytest.mark.parametrize("predicate,is_excluded", [
    ("coverage-of", False),          # tire-YOK → startswith("coverage-of-") False
    ("coverage-of-x", True),         # tam-önek → dışlanır
    ("coverage-ofid", False),        # önek-benzeri-AMA-tire-yok → dahil
])
def test_coverage_prefix_boundary(predicate, is_excluded):
    """F2 SINIR: dışlama 'coverage-of-' tam-öneki-arar; 'coverage-of' (tiresiz)
    veya 'coverage-ofid' gibi-yakın-önekler DAHİL-sayılır."""
    claims = [_claim("c1", "DOCTRINAL", predicate)]
    result = _risk_level_for(claims, {"c1": {"value": "REFUTED"}})
    assert result == ("low" if is_excluded else "high")


# ───────────── V1/V2: per_claim erişim-dalları (dict vs nesne) ─────────────
@pytest.mark.parametrize("value,expected", [("REFUTED", "high"),
                                            ("ESCALATED", "high"),
                                            ("INCONCLUSIVE", "medium"),
                                            ("VERIFIED", "low")])
def test_dict_access_branch(value, expected):
    """V1: per_claim değeri dict ise a['value'] okunur."""
    claims = [_claim("c1")]
    assert _risk_level_for(claims, {"c1": {"value": value}}) == expected


@pytest.mark.parametrize("value,expected", [("REFUTED", "high"),
                                            ("ESCALATED", "high"),
                                            ("INCONCLUSIVE", "medium"),
                                            ("VERIFIED", "low")])
def test_object_access_branch(value, expected):
    """V2: per_claim değeri nesne ise a.value okunur (gerçek Adjudication)."""
    claims = [_claim("c1")]
    adj = Adjudication(claim_id="c1", value=value, divergence="UNANIMOUS",
                       rung="R0")
    assert _risk_level_for(claims, {"c1": adj}) == expected


def test_dict_and_object_mixed():
    """Aynı-pakette dict ve nesne-değerleri birlikte-çalışır."""
    claims = [_claim("c1"), _claim("c2")]
    per = {"c1": {"value": "VERIFIED"},
           "c2": Adjudication("c2", "REFUTED", "SPLIT", "R2")}
    assert _risk_level_for(claims, per) == "high"


# ───────────────── R1-R4: _risk_level karar-dalları ─────────────────
@pytest.mark.parametrize("values,expected", [
    (["REFUTED"], "high"),
    (["ESCALATED"], "high"),
    (["INCONCLUSIVE"], "medium"),
    (["VERIFIED"], "low"),
    (["SUPPORTS"], "low"),
    (["OPEN"], "low"),
    ([], "low"),
])
def test_risk_level_decision_branches(values, expected):
    """R1-R3: REFUTED|ESCALATED→high, INCONCLUSIVE→medium, diğer→low;
    boş-liste→low (fallback-dal)."""
    assert _risk_level(values) == expected


@pytest.mark.parametrize("values,expected", [
    (["VERIFIED", "REFUTED", "INCONCLUSIVE"], "high"),
    (["INCONCLUSIVE", "REFUTED"], "high"),
    (["ESCALATED", "INCONCLUSIVE"], "high"),
    (["VERIFIED", "INCONCLUSIVE"], "medium"),
])
def test_risk_level_priority_refuted_beats_inconclusive(values, expected):
    """R4: REFUTED/ESCALATED, INCONCLUSIVE'dan-ÖNCE-kontrol-edilir;
    liste-sırasından-bağımsız-yüksek-kazanır."""
    assert _risk_level(values) == expected


@pytest.mark.parametrize("bad_position", [0, 1, 2])
def test_refuted_at_any_position_raises_risk(bad_position):
    """REFUTED listenin herhangi-bir-yerindeyse high-döner (sıra-duyarsız)."""
    values = ["VERIFIED", "VERIFIED", "VERIFIED"]
    values[bad_position] = "REFUTED"
    assert _risk_level(values) == "high"


# ───────────────── S1: boş ve tamamen-dışlanan listeler ─────────────────
def test_empty_claims_list_is_low():
    """S1: hiç-iddia-yok → values=[] → low (döngü-girmiyor)."""
    assert _risk_level_for([], {}) == "low"


@pytest.mark.parametrize("claims", [
    [_claim("c1", "DOCTRINAL", "coverage-of-a")],
    [_claim("c1", "DOCTRINAL", "coverage-of-a"),
     _claim("c2", "DOCTRINAL", "coverage-of-b")],
])
def test_all_claims_excluded_is_low(claims):
    """S1: TÜM iddialar dışlanırsa values=[] → low (hiç-değer-okunmaz)."""
    assert _risk_level_for(claims, {}) == "low"


def test_excluded_claim_value_never_accessed():
    """Dışlanan-iddianın per_claim-değeri okunMAZ — boş dict bile
    KeyError-vermez (tembel-filtre+değer-erişimi ayrımı)."""
    claims = [_claim("c1", "DOCTRINAL", "coverage-of-a")]
    assert _risk_level_for(claims, {}) == "low"


def test_partial_exclusion_uses_remaining_claims():
    """Bir-iddia dışlanır, diğeri-kalır → kalanın-değeri-belirler."""
    claims = [_claim("c1", "DOCTRINAL", "coverage-of-a"),
              _claim("c2", "MACHINE_CHECKABLE", "is-fast")]
    assert _risk_level_for(claims, {"c2": {"value": "REFUTED"}}) == "high"
    assert _risk_level_for(claims, {"c2": {"value": "VERIFIED"}}) == "low"


# ───────────────── Çoklu-iddia senaryoları ─────────────────
@pytest.mark.parametrize("values,expected", [
    (["VERIFIED", "VERIFIED", "VERIFIED"], "low"),
    (["VERIFIED", "INCONCLUSIVE", "VERIFIED"], "medium"),
    (["VERIFIED", "ESCALATED", "VERIFIED"], "high"),
])
def test_multiple_claims_risk_aggregation(values, expected):
    """Birden-çok dahil-iddianın değerleri-birleşip-tek-risk-verir."""
    claims = [_claim("c%d" % i, "MACHINE_CHECKABLE", "p%d" % i)
              for i in range(len(values))]
    per = {c.claim_id: {"value": v} for c, v in zip(claims, values)}
    assert _risk_level_for(claims, per) == expected


def test_meta_claim_refusal_never_raises_risk():
    """Doktrin-büyüme-koruması: dışlanan meta-iddianın REFUTED-değeri
    riski-high-YAPMAZ (§5.3 kural-2 ile-gelen-koruma)."""
    claims = [_claim("c1", "DOCTRINAL", "coverage-of-perf"),
              _claim("c2", "MACHINE_CHECKABLE", "is-fast")]
    per = {"c1": {"value": "REFUTED"}, "c2": {"value": "VERIFIED"}}
    assert _risk_level_for(claims, per) == "low"


def test_non_doctrinal_meta_claim_refusal_counts():
    """MACHINE_CHECKABLE bir coverage-of-* iddiası dışlanMAZ → REFUTED-high."""
    claims = [_claim("c1", "MACHINE_CHECKABLE", "coverage-of-perf")]
    assert _risk_level_for(claims, {"c1": {"value": "REFUTED"}}) == "high"


# ───────────────── Üretim-sınırları (hata-dalları) ─────────────────
def test_missing_claim_id_raises_keyerror():
    """SINIR: per_claim'de-olmayan claim_id → KeyError (sessiz-geçiş-YOK)."""
    claims = [_claim("c1")]
    with pytest.raises(KeyError):
        _risk_level_for(claims, {})


def test_dict_value_missing_value_key_raises():
    """SINIR: per_claim dict'i 'value' anahtarı-içermiyorsa → KeyError('value')."""
    claims = [_claim("c1")]
    with pytest.raises(KeyError):
        _risk_level_for(claims, {"c1": {"wrong": "x"}})


def test_plain_string_value_raises_attributeerror():
    """SINIR: per_claim değeri dict-değil-ve .value'i-yoksa (örn. düz-str)
    → AttributeError. Üretim dict-veya-nesne-bekler (duck-typing-sınırı)."""
    claims = [_claim("c1")]
    with pytest.raises(AttributeError):
        _risk_level_for(claims, {"c1": "VERIFIED"})


@pytest.mark.parametrize("result", ["low", "medium", "high"])
def test_return_type_is_str(result):
    """Sözleşme: dönüş her-zaman str (üç-geçerli-değerden-biri)."""
    claims = [_claim("c1")]
    value = {"low": "VERIFIED", "medium": "INCONCLUSIVE", "high": "REFUTED"}[result]
    out = _risk_level_for(claims, {"c1": {"value": value}})
    assert isinstance(out, str)
    assert out == result
