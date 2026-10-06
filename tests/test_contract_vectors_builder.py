"""Builder-side contract-vector tests — build_contract_vectors.py (68+ satır).

Mevcut tests/test_contract_vectors.py, kaydedilmiş vektör DOSYALARINI
(docs/standard-test-vectors/*.json) çalıştırır; bu test dosyası ÜRETECİ
fonksiyonları çalıştırır:

  * build_ladder_cases   (68 satır) — §7 karar tablosu vektörleri; her
    durumda reference ladder (veridict.ladder.adjudicate) ile spec-only
    ladder (examples.spec_verifier.adjudicate_spec) birebir aynı sonucu
    verir (builder içinde assert edilir).
  * build_watcher_cases  (39 satır) — §6.3/§6.4 watcher oturum sözleşmesi:
    confidence [0,1] clamps, kötü stance/None/exception/malformed/deadline
    → abstain (None), tier asla W1a değil (ceiling).

Güvenlik açısından kritik: eğer builder karar tablosunu yanlış üretirse,
kaydedilmiş vektörleri çalıştıran testler bunu GÖREMEZ (dosya sabittir).
Bu test, canlı koddan üretilen tablo ile işlenmiş vektörler arasındaki
sürüklenmeyi (drift) yakalar.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from build_contract_vectors import build_ladder_cases, build_watcher_cases  # noqa: E402

from examples.spec_verifier import adjudicate_spec  # noqa: E402
from veridict.ladder import adjudicate  # noqa: E402
from veridict.policy import PolicyDeclaration, Thresholds  # noqa: E402
from veridict.schemas import Claim, EvidenceItem  # noqa: E402

VEC = os.path.join(ROOT, "docs", "standard-test-vectors")

# Kaydedilmiş karar tablosu (builder'dan bağımsız olarak sabitlendi):
# (case_id, value, rung, divergence)
EXPECTED_LADDER = [
    ("R0-machine-univocal",              "VERIFIED",     "R0", "UNANIMOUS"),
    ("R1-w1a-refuted",                   "REFUTED",      "R1", "UNANIMOUS"),
    ("R1-doctrine-cannot-overturn",      "VERIFIED",     "R1", "UNANIMOUS"),
    ("R1-w1b-signal-stays-verified",     "VERIFIED",     "R2", "UNANIMOUS"),
    ("R2-w1b-only-refute",               "INCONCLUSIVE", "R2", "UNANIMOUS"),
    ("R3-critical-split-escalates",      "ESCALATED",    "R3", "SPLIT"),
    ("R4-doctrinal-unanimous-support",   "VERIFIED",     "R4", "UNANIMOUS"),
    ("R4-doctrinal-single-refute-refuted", "REFUTED",    "R4", "MAJORITY"),
    ("R4-doctrinal-split-inconclusive",  "INCONCLUSIVE", "R4", "SPLIT"),
    ("R4-w3-only-never-verifies",        "INCONCLUSIVE", "R4", "UNANIMOUS"),
    ("R4-first-no-evidence",             "INCONCLUSIVE", "R4", "UNANIMOUS"),
]


@pytest.fixture(scope="module")
def ladder_cases():
    return build_ladder_cases()


@pytest.fixture(scope="module")
def watcher_cases():
    return build_watcher_cases()


# ------------------------------------------------------------------ ladder builder

def test_ladder_builder_produces_full_decision_table(ladder_cases):
    """11 vaka, her biri benzersiz id ile — §7 tablosu eksiksiz."""
    assert len(ladder_cases) == 11
    ids = [c["id"] for c in ladder_cases]
    assert ids == [e[0] for e in EXPECTED_LADDER]     # sıralı + tekrarsız
    assert len(set(ids)) == len(ids)


def test_ladder_builder_matches_expected_decision_table(ladder_cases):
    """Üretilen tablo kaydedilmiş karar tablosuyla birebir aynı."""
    by_id = {c["id"]: c for c in ladder_cases}
    for cid, value, rung, div in EXPECTED_LADDER:
        exp = by_id[cid]["expected"]
        assert exp["value"] == value, cid
        assert exp["rung"] == rung, cid
        assert exp["divergence"] == div, cid


def test_ladder_builder_reproduces_committed_vectors():
    """Builder canlı koddan üretildiğinde işlenmiş JSON vektörlerle AYNI.

    Sürüklenme koruması: reference ladder'da bir değişiklik bu vektörleri
    değiştirirse, docs altındaki işlenmiş vektörlerle uyum bozulur.
    """
    with open(os.path.join(VEC, "ladder_vectors.json"), encoding="utf-8") as f:
        stored = json.load(f)
    assert stored["cases"] == build_ladder_cases()


def test_ladder_builder_is_deterministic():
    a = build_ladder_cases()
    b = build_ladder_cases()
    assert a == b


def test_ladder_vector_schema_is_stable(ladder_cases):
    """Her vaka harici uygulamanın ihtiyaç duyduğu alanları taşıyor."""
    for c in ladder_cases:
        assert set(c) >= {"id", "claim", "evidence", "expected",
                          "divergence_tolerance", "criticality"}
        assert set(c["expected"]) >= {"value", "rung", "divergence"}
        assert c["claim"]["verifiability"] in ("MACHINE_CHECKABLE", "DOCTRINAL")


# ------------------------------------------------------------------ spec parity (bağımsız)

def _policy():
    return PolicyDeclaration(policy_id="vectors", mode="GATE",
                             criticality=("payments",),
                             thresholds=Thresholds(),
                             divergence_tolerance=1 / 3)


def _claim(verif, crit=None):
    return Claim(claim_id="c1", task_id="t", subject="s", predicate="p",
                 scope="s", summary="sum", derived_from="d",
                 verifiability=verif, falsifiable_by=("x",), critical_class=crit)


def _ev(tier, stance, conf, eid):
    return EvidenceItem(
        evidence_id=eid, claim_id="c1",
        evidence_class="TEST_EXECUTION" if tier == "W1a" else "JURY_OPINION",
        tier=tier,
        producer={"kind": "jury", "identity": "p", "version": "1.0.0",
                  "family": "f"},
        artifact_ref="art",
        reproducibility={"deterministic": tier == "W1a",
                         "rerun_recipe": {"cmd": "pytest"} if tier == "W1a" else None},
        stance=stance, confidence=conf, rationale="vector",
    )


@pytest.mark.parametrize("verif,crit,evidence", [
    # R1: W1a refutation, W2 support → REFUTED (machine-checkable önceliği)
    ("MACHINE_CHECKABLE", None, [("W1a", "REFUTES", 1.0, "e1"),
                                 ("W2", "SUPPORTS", 0.8, "e2")]),
    # R3: critical-class (payments) doctrinal SPLIT → ESCALATED
    ("DOCTRINAL", "payments", [("W2", "SUPPORTS", 0.8, "e1"),
                               ("W2", "REFUTES", 0.8, "e2")]),
    # R4: W3 yalnız → asla VERIFIED (kanıt yetersiz)
    ("DOCTRINAL", None, [("W3", "SUPPORTS", 0.8, "e1")]),
])
def test_reference_ladder_and_spec_only_ladder_agree(verif, crit, evidence):
    """Reference ladder ile spec-only implementation bağımsız olarak aynı sonucu verir."""
    pol = _policy()
    claim = _claim(verif, crit)
    items = [_ev(t, s, c, i) for t, s, c, i in evidence]
    adj = adjudicate(claim, items, pol)
    spec = adjudicate_spec(claim.to_dict(), [i.to_dict() for i in items],
                           list(pol.criticality), pol.divergence_tolerance)
    assert adj.value == spec
    # eşlik: karar tablosundaki bilinen değerler
    if evidence and evidence[0][0] == "W1a" and evidence[0][1] == "REFUTES":
        assert adj.value == "REFUTED"
    if crit == "payments" and {e[1] for e in evidence} == {"SUPPORTS", "REFUTES"}:
        assert adj.value == "ESCALATED"
    if all(t == "W3" for t, _, _, _ in evidence):
        assert adj.value == "INCONCLUSIVE"


# ------------------------------------------------------------------ watcher builder

def test_watcher_builder_produces_session_contract_cases(watcher_cases):
    """10 vaka: normal + clamp + abstain + ceiling + deadline."""
    assert len(watcher_cases) == 10
    ids = [c["id"] for c in watcher_cases]
    assert len(set(ids)) == len(ids)


def test_watcher_builder_reproduces_committed_vectors():
    with open(os.path.join(VEC, "watcher_vectors.json"), encoding="utf-8") as f:
        stored = json.load(f)
    assert stored["cases"] == build_watcher_cases()


def test_watcher_builder_is_deterministic():
    assert build_watcher_cases() == build_watcher_cases()


def test_watcher_confidence_is_clamped_to_unit_interval(watcher_cases):
    """7.5 → 1.0; -3.0 → 0.0 (confidence asla [0,1] dışına çıkmaz)."""
    by_id = {c["id"]: c["expected"] for c in watcher_cases}
    assert by_id["confidence-clamps-high"]["confidence"] == 1.0
    assert by_id["confidence-clamps-low"]["confidence"] == 0.0
    for c in watcher_cases:
        if c["expected"] is not None:
            conf = c["expected"]["confidence"]
            assert 0.0 <= conf <= 1.0


@pytest.mark.parametrize("case_id", [
    "bad-stance-abstains",      # 'MAYBE' geçerli stance değil
    "none-abstains",            # None → çekimser
    "exception-abstains",       # exception → çekimser (çökme değil)
    "malformed-shape-abstains", # yanlış tuple şekli → çekimser
    "deadline-abstains",        # deadline aşımı → çekimser
])
def test_watcher_failure_modes_abstain(watcher_cases, case_id):
    """Tüm hata kipleri ABSTAIN (None) — sessiz kötü kanıt ÜRETİLMEZ."""
    by_id = {c["id"]: c["expected"] for c in watcher_cases}
    assert by_id[case_id] is None


def test_watcher_ceiling_never_returns_w1a(watcher_cases):
    """Watcher asla W1a dönemez; tier manifest ceiling'ine bağlı."""
    for c in watcher_cases:
        if c["expected"] is None:
            continue
        assert c["expected"]["tier"] != "W1a"
    ceiling = {c["id"]: c["expected"] for c in watcher_cases}["ceiling-never-w1a"]
    assert ceiling["tier"] == "W3"                    # max_tier=W3 → W3
    assert ceiling["evidence_class"] == "TEST_EXECUTION"


def test_watcher_normal_case_produces_evidence(watcher_cases):
    normal = {c["id"]: c["expected"] for c in watcher_cases}["normal-support"]
    assert normal["stance"] == "SUPPORTS"
    assert normal["confidence"] == pytest.approx(0.9)
    assert normal["producer_kind"] == "watcher"


def test_watcher_list_output_is_accepted_like_tuple(watcher_cases):
    """list ['REFUTES', 0.8, 'x'] tuple ile aynı şekilde kabul edilir."""
    out = {c["id"]: c["expected"] for c in watcher_cases}["list-output-accepted"]
    assert out["stance"] == "REFUTES"
    assert out["confidence"] == pytest.approx(0.8)
