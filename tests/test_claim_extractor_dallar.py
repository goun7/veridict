"""claim_extractor dal-kesen testleri.

Dal haritasi (her public fonksiyon icin basari/basarisiz/sinir dallari):
  D1  MACHINE satiri -> claim alanlari (subject/predicate/slug/verifiability)
  D2  DOCTRINE satiri -> DOCTRINAL + falsifiable_by=(jury,)
  D3  sinif etiketi: MACHINE(crit) critical_class gelir; etiketsiz None
  D4  gecersiz intent satiri -> ValueError (parametreli) +
      SINIR: body sadece bosluk ise satir gecilir (bos predicate, summary ' ')
  D5  ayni intent satiri iki kez -> duplicate claim_id ValueError
  D6  farkli sinif etiketi + ayni summary -> yine duplicate (id summary'e dayali)
  D7  MACHINE vs DOCTRINE ayni summary -> farkli claim_id (verifiability id'ye girer)
  D8  ayni ilk-8-kelime ama farkli kuyruk -> predicate ayni, claim_id farkli
  D9  has_existing_tests True/False -> existing-test-suite-passes varligi
  D10 forbidden-constructs-absent her zaman eklenir
  D11 bos intent + has_existing_tests=False -> tam 1 claim
  D12 claim_id deterministik; task_id degisince id degisir
  D13 make_claim (direkt) -> tum alanlar yansir, scope repo, status OPEN
  D14 claim_id digest'ten bagimsiz (ayni task+summary, farkli digest -> ayni id)
  D15 extract Claim nesneleri dondurur; task_id/task alanlari tam
"""
from __future__ import annotations

import pytest

from veridict.claim_extractor import ClaimExtractor
from veridict.schemas import Claim, TaskManifest
from veridict.utils import sha256_hex


def _gorev(intent=(), has_existing_tests: bool = False,
           task_id: str = "task-1") -> TaskManifest:
    return TaskManifest(
        task_id=task_id, artifact_path="/repo/artifact",
        actor_identity="actor-1", intent_lines=tuple(intent),
        criticality=(), has_existing_tests=has_existing_tests, pytest_args=())


@pytest.mark.parametrize("satir, beklenen_slug", [
    ("MACHINE: x equals 1", "x-equals-1"),
    ("  MACHINE:   x equals 1  ", "x-equals-1"),
    ("MACHINE(auth): token expires after 3600 seconds", "token-expires-after-3600-seconds"),
    ("DOCTRINE: the module handles concurrent writes safely", "the-module-handles-concurrent-writes-safely"[:59]),
])
class TestMachineDogrulamaDallari:
    """D1/D2: MACHINE ve DOCTRINE satirlarindan dogru claim uretimi."""

    def test_machine_satiri_alanlari(self, satir, beklenen_slug):
        claims = ClaimExtractor().extract(_gorev([satir]), "digest-aa")
        intent_claims = [c for c in claims if c.subject == "intent"]
        assert len(intent_claims) == 1
        c = intent_claims[0]
        assert c.predicate == beklenen_slug
        assert c.summary == satir.split(":", 1)[1].strip()
        assert c.derived_from == "digest-aa"
        assert c.scope == "repo"
        assert c.task_id == "task-1"
        if satir.strip().upper().startswith("MACHINE"):
            assert c.verifiability == "MACHINE_CHECKABLE"
            assert c.falsifiable_by == ("test_execution", "static_analysis")
        else:
            assert c.verifiability == "DOCTRINAL"
            assert c.falsifiable_by == ("jury",)


class TestDogrulanabilirlikDallari:
    """D2: DOCTRINE oznitelikleri ve D3: sinif etiketi dallari."""

    def test_doctrine_satiri_doctrinal_ve_juri(self):
        claims = ClaimExtractor().extract(
            _gorev(["DOCTRINE: policy is conservative on upgrades"]), "d")
        c = next(x for x in claims if x.subject == "intent")
        assert c.verifiability == "DOCTRINAL"
        assert c.falsifiable_by == ("jury",)

    @pytest.mark.parametrize("satir, beklenen_sinif", [
        ("MACHINE(critical-sec): x equals 1", "critical-sec"),
        ("DOCTRINE(availability): no data loss on crash", "availability"),
        ("MACHINE: x equals 1", None),
        ("DOCTRINE: x equals 1", None),
    ])
    def test_sinif_etiketi_critical_class(self, satir, beklenen_sinif):
        claims = ClaimExtractor().extract(_gorev([satir]), "d")
        c = next(x for x in claims if x.subject == "intent")
        assert c.critical_class == beklenen_sinif


class TestGecersizIntentDallari:
    """D4: her gecersiz format ValueError ile reddedilir."""

    @pytest.mark.parametrize("satir", [
        "FREEFORM: no tag here",
        "machine: lower case kind",
        "MACHINE",
        "MACHINE:",
        "MACHINE x equals 1",
        "MACHINE(ABC): upper case class",
        "MACHINE(): empty class",
        "",
        "    ",
        "AUDIT: not a known kind",
        "MACHINE: ok\nDOCTRINE: newline inside body",
    ])
    def test_gecersiz_satir_value_error(self, satir):
        with pytest.raises(ValueError, match="invalid intent line"):
            ClaimExtractor().extract(_gorev([satir]), "d")

    def test_hata_mesaji_satiri_icerir(self):
        with pytest.raises(ValueError) as exc:
            ClaimExtractor().extract(_gorev(["nope: bad"]), "d")
        assert "nope: bad" in str(exc.value)


class TestBoslukBodySiniri:
    """D4 (sinir): body sadece boşluklardan olusursa satir GECERLI sayilir.

    _LINE regexi `(.+?)` bosluk karakterine de izin verdigi icin "MACHINE:  "
    bir claim uretir — summary ' ' (tek bosluk) ve predicate '' (bos slug)
    ile. Bu bir üretim kenar-durumudur: bos falsifiable statement dogrulamadan
    gecer (raporlandigi uzere uretime dokunulmaz).
    """

    def test_bosluk_body_reddedilir(self):
        """D4 (DUZELTILDI DALGA-6-F1): bos-ruhu-garantisi — body yalniz
        bosluksa ValueError ('empty statement')."""
        with pytest.raises(ValueError, match="empty statement"):
            ClaimExtractor().extract(_gorev(["MACHINE:   "]), "d")

    def test_tab_ve_bosluk_karmasi_da_reddedilir(self):
        with pytest.raises(ValueError, match="empty statement"):
            ClaimExtractor().extract(_gorev(["DOCTRINE: \t "]), "d")


class TestTekrarDallari:
    """D5/D6/D7/D8: claim_id cakisma ve ayirt etme dallari."""

    def test_ayni_satir_iki_kez_cakisma(self):
        with pytest.raises(ValueError, match="duplicate claim_id"):
            ClaimExtractor().extract(
                _gorev(["MACHINE: x equals y", "MACHINE: x equals y"]), "d")

    def test_farkli_sinif_ayni_summary_yine_cakisir(self):
        # claim_id = sha256(task_id|summary|verifiability) — sinif etiketi
        # id'ye girmedigi icin iki farkli etiket ayni id'ye dusmeli.
        with pytest.raises(ValueError, match="duplicate claim_id"):
            ClaimExtractor().extract(
                _gorev(["MACHINE(a): x equals y", "MACHINE(b): x equals y"]), "d")

    def test_machine_ve_doctrine_ayni_summary_farkli_id(self):
        claims = ClaimExtractor().extract(
            _gorev(["MACHINE: x equals y", "DOCTRINE: x equals y"]), "d")
        ids = [c.claim_id for c in claims if c.subject == "intent"]
        assert len(ids) == 2
        assert len(set(ids)) == 2

    def test_ayni_slug_farkli_kuyruk_farkli_id(self):
        # _slug 8 kelimeyle sinirlidir; iki uzun intent ayni slug'a
        # dusse bile claim_id summary'den tintlendigi icin ayrilirlar.
        uzun1 = "alpha beta gamma delta epsilon zeta eta theta iota extra one"
        uzun2 = "alpha beta gamma delta epsilon zeta eta theta iota extra two"
        claims = ClaimExtractor().extract(_gorev([f"MACHINE: {uzun1}",
                                                  f"MACHINE: {uzun2}"]), "d")
        intent = [c for c in claims if c.subject == "intent"]
        assert len(intent) == 2
        assert intent[0].predicate == intent[1].predicate
        assert intent[0].claim_id != intent[1].claim_id
        assert intent[0].summary != intent[1].summary


class TestOtomatikClaimDallari:
    """D9/D10/D11: has_existing_tests ve forbidden-constructs dallari."""

    def test_existing_tests_true_ek_claim_katar(self):
        claims = ClaimExtractor().extract(
            _gorev(["MACHINE: x equals 1"], has_existing_tests=True), "d")
        predicates = {c.predicate for c in claims}
        assert "existing-test-suite-passes" in predicates
        extra = next(c for c in claims if c.predicate == "existing-test-suite-passes")
        assert extra.subject == "repo"
        assert extra.critical_class is None
        assert extra.verifiability == "MACHINE_CHECKABLE"

    def test_existing_tests_false_ek_claim_yok(self):
        claims = ClaimExtractor().extract(
            _gorev(["MACHINE: x equals 1"], has_existing_tests=False), "d")
        assert all(c.predicate != "existing-test-suite-passes" for c in claims)
        assert len(claims) == 2

    def test_forbidden_constructs_her_zaman(self):
        claims = ClaimExtractor().extract(_gorev([]), "d")
        assert len(claims) == 1
        assert claims[0].predicate == "forbidden-constructs-absent"
        assert claims[0].verifiability == "MACHINE_CHECKABLE"
        assert claims[0].falsifiable_by == ("static_analysis",)

    def test_bos_intent_ve_testsiz_tam_bir_claim(self):
        claims = ClaimExtractor().extract(
            _gorev([], has_existing_tests=False), "d")
        assert len(claims) == 1
        assert claims[0].subject == "repo"

    def test_n_intent_arti_iki(self):
        claims = ClaimExtractor().extract(
            _gorev(["MACHINE: a", "DOCTRINE: b", "MACHINE: c"],
                   has_existing_tests=True), "d")
        assert len(claims) == 5


class TestIdDeterminizmi:
    """D12/D14: claim_id uretim determinizmi."""

    def test_ayni_girdi_ayni_id(self):
        a = ClaimExtractor().extract(_gorev(["MACHINE: x equals y"]), "d")
        b = ClaimExtractor().extract(_gorev(["MACHINE: x equals y"]), "d")
        assert a[0].claim_id == b[0].claim_id

    def test_farkli_task_id_farkli_id(self):
        a = ClaimExtractor().extract(
            _gorev(["MACHINE: x equals y"], task_id="task-a"), "d")
        b = ClaimExtractor().extract(
            _gorev(["MACHINE: x equals y"], task_id="task-b"), "d")
        assert a[0].claim_id != b[0].claim_id

    def test_id_beklenen_sha256_kesimi(self):
        summary = "x equals y"
        claims = ClaimExtractor().extract(_gorev(["MACHINE: " + summary]), "d")
        beklenen = sha256_hex(f"task-1|{summary}|MACHINE_CHECKABLE")[:16]
        assert claims[0].claim_id == beklenen

    def test_id_digest_bagimsiz(self):
        # D14: claim_id digest'a degil task+summary+verifiability'e bagli.
        a = ClaimExtractor().extract(_gorev(["MACHINE: x equals y"]), "d-1")
        b = ClaimExtractor().extract(_gorev(["MACHINE: x equals y"]), "d-2")
        assert a[0].claim_id == b[0].claim_id
        assert a[0].derived_from == "d-1"
        assert b[0].derived_from == "d-2"


class TestMakeClaim:
    """D13: make_claim public imzasi — tum alanlar Claim'e aynen yansir."""

    def test_butun_alanlar_yansir(self):
        claim = ClaimExtractor().make_claim(
            _gorev(), "digest-9", subject="repo", predicate="p-1",
            summary="summary text", verifiability="MIXED",
            falsifiable_by=("test_execution", "jury"), critical_class="cls-1")
        assert isinstance(claim, Claim)
        assert claim.claim_id
        assert claim.task_id == "task-1"
        assert claim.subject == "repo"
        assert claim.predicate == "p-1"
        assert claim.summary == "summary text"
        assert claim.derived_from == "digest-9"
        assert claim.verifiability == "MIXED"
        assert claim.falsifiable_by == ("test_execution", "jury")
        assert claim.critical_class == "cls-1"
        assert claim.status == "OPEN"

    @pytest.mark.parametrize("sinif", [None, "crit-a"])
    def test_critical_class_none_ve_dolu(self, sinif):
        claim = ClaimExtractor().make_claim(
            _gorev(), "d", subject="intent", predicate="p", summary="s",
            verifiability="DOCTRINAL", falsifiable_by=("jury",),
            critical_class=sinif)
        assert claim.critical_class is sinif or claim.critical_class == sinif

    def test_scope_her_zaman_repo(self):
        # D13 sinir: scope cagirida verilemez — her zaman "repo".
        claim = ClaimExtractor().make_claim(
            _gorev(), "d", subject="intent", predicate="p", summary="s",
            verifiability="DOCTRINAL", falsifiable_by=("jury",),
            critical_class=None)
        assert claim.scope == "repo"

    def test_id_summary_ve_verifiability_bileseni(self):
        task = _gorev()
        a = ClaimExtractor().make_claim(
            task, "d", subject="x", predicate="p", summary="s",
            verifiability="DOCTRINAL", falsifiable_by=("jury",),
            critical_class=None)
        b = ClaimExtractor().make_claim(
            task, "d", subject="x", predicate="p", summary="s",
            verifiability="MACHINE_CHECKABLE", falsifiable_by=("t",),
            critical_class=None)
        assert a.claim_id != b.claim_id
