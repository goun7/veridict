"""Dal-kesen (branch-cutting) testler: veridict/conformance.py

Kapsanan public API: run_conformance_suite(session, registry_factory=None).
Bunun üzerinden 13	checkin (C1..C13) HER dalı kesilecek şekilde çalıştırılır;
ayrıca izolasyon çekirdeği _check ve prob-talebi _probe_claim doğrudan
sınanır (bunlar private olsa da izolasyon sözleşmesinin ta kendileridirler).

DAL LİSTESİ (run_conformance_suite):
  * dönüş şeması: {watcher_id, conformant, checks[]}; her check
    {id, name, passed, detail}; conformant = hepsi passed
  * C1 manifest round-trip: başarılı; başarısız (to_dict'e müdahale)
  * C2 tier tavanı: izinli W1b/W2/W3 => tier == max_tier; W1a imkânsız
    (_CEILING_TIER'de W1a ANAHTARI YOK => KeyError, asla W1a üretilmez)
  * C3 körlük: fn tam olarak (summary, ref) alır — ref, path verilince path,
    verilmezse digest; hata fırlatsa bile argümanlar kaydedilir
  * C4 hata => istisna (abstain); Exception değil BaseException SIZAR
  * C5 None => istisna
  * C6 izin listesi dışı stance => istisna; izinliler => kanıt
  * C7 güven [0,1]'e kıstırılır (sınır: 0.0/1.0; taşma: 7.3->1.0; str/bool;
    nan->1.0, inf->1.0, -inf->0.0)
  * C8 kanıt şekli: producer kind=watcher/family=watcher_id,
    evidence_class bildirilen kümede, claim_id taşınır; fn istisna yapınca
    "watcher produced no evidence" ile başarısız
  * C9 kayıt defteri: varsayılan scratch registry; verilen factory kullanılır;
    factory'nin verify_manifest başarısız => C9 başarısız
  * C10 kaynak zaman aşımı: manifest timeout => istisna; açık
    timeout_seconds manifest değerini EZER; deadline 0/None => satır-içi çalışma
  * C11 transport determinizmi: 3 koşu özdeş (kit'in sabit probe fn'i);
    durumlu doctrine fn'i GÖRÜLMEZ (B5)
  * C12 kanıt-sınıfı tavanı: bildirilen küme içinde; BOŞ bildiri => "vacuous"
    (ama o zaman transport üretim yapamaz — C2/C7/C8/C11 IndexError ile düşer)
  * C13 sandbox/bütçe tutarlılığı: inprocess + bütçe>0 => başarısız;
    bütçe 0/negatif => geçer; sayısal olmayan bütçe => ValueError izole edilir

BULGULAR (production koduna DOKUNULMADI — burada belgelendi):
  B1: run_session, evidence_classes[0] indeksini try bloğunun DIŞINDA yapar —
      boş evidence_classes bildirilince IndexError yükselir ve _check
      tarafından "başarısız check" olarak izole edilir (istisna/abstain değil).
  B2: negatif cost_budget "tutarlı" kabul edilir (sadece > 0 denetlenir).
  B3: sandbox_level'ın sadece "inprocess" değeri denetlenir.
  B4: run_session sadece Exception yakalar — KeyboardInterrupt/SystemExit
      BaseException oldukları için audit'i çökertebilirler (C4'ün izolasyonu
      onları kapsamaz).
  B5: C11 determinizmi session.doctrine_fn'i DEĞİL, kit'in kendi sabit
      lambda'ını çağırır — durumsuz/rastgele bir watcher fn'i C11'i geçer;
      C11 yalnızca transport'u (run_session) sınar, doctrine'i sınar.
  B6: C1/C2/C4/C5/C6/C8'nin "ihlal" dallarının bir kısmı public API ile
      erişilemez (run_session sözleşmesi ihlali imkânsız kılar) — savunma
      amaçlı assertionlardır, docstring'lerindeki "lower bound" notuyla
      tutarlıdır.
"""
from __future__ import annotations

import threading
import time

import pytest

from veridict import conformance
from veridict.conformance import _EID, _check, _probe_claim, run_conformance_suite
from veridict.keys import KeyStore
from veridict.ledger import Ledger
from veridict.schemas import Claim, EvidenceItem
from veridict.watchers import (
    EID_SALT,
    ManifestRegistry,
    WatcherManifest,
    WatcherSession,
    run_session,
)

_CHECK_ADLARI = [
    ("C1", "manifest invariants"), ("C2", "tier ceiling (never W1a)"),
    ("C3", "blindness (inputs)"), ("C4", "abstain on error"),
    ("C5", "abstain on None"), ("C6", "abstain on bad stance"),
    ("C7", "confidence clamp"), ("C8", "evidence shape"),
    ("C9", "registry verification"), ("C10", "resource deadline"),
    ("C11", "transport determinism"), ("C12", "evidence-class ceiling"),
    ("C13", "sandbox/budget coherence"),
]


def _manifest(**over) -> WatcherManifest:
    base: dict = dict(
        watcher_id="dal-watcher", name="Dal Test Watcher", version="0.1.0",
        producer={"identity": "dal-test", "maintainer": "dal-org"},
        capabilities={"evidence_classes": ("WATCHER_REPORT",), "max_tier": "W1b",
                      "subscribes_to": ("*",)},
        resource_class={"timeout_seconds": 0, "cost_budget": 0,
                        "sandbox_level": "none"},
        integrity={"code_hash": "d" * 64, "update_policy": "manual"},
    )
    base.update(over)
    return WatcherManifest(**base)


def _iddia() -> Claim:
    return Claim(claim_id="dal-claim", task_id="dal", subject="dal",
                 predicate="dal-probe", scope="probe",
                 summary="dal test summary", derived_from="dagilim-abc",
                 verifiability="DOCTRINAL", falsifiable_by=("watcher",),
                 critical_class=None)


def _session(fn=None, manifest: WatcherManifest | None = None,
             **over) -> WatcherSession:
    if manifest is None:
        manifest = _manifest(**over)
    return WatcherSession(manifest, fn or (lambda s, r: ("SUPPORTS", 0.8, "probe")))


def _fırlat(exc: BaseException):
    raise exc


def _check_al(rapor: dict, cid: str) -> dict:
    return next(c for c in rapor["checks"] if c["id"] == cid)


def _başarısızlar(rapor: dict) -> set[str]:
    return {c["id"] for c in rapor["checks"] if not c["passed"]}


# ---------------------------------------------------------------------------
# rapor şeması + tam uyumlu (başarılı) yol
# ---------------------------------------------------------------------------

class TestRaporŞeması:
    """run_conformance_suite dönüş şeması ve tam-uyumlu başarı dalı.

    Dallar: conformant=True (13 check de geçer); her check {id,name,passed,
    detail} anahtarlarına sahip; detail her geçen check için gerçek değer;
    watcher_id manifest'ten gelir; C10 manifest timeout olmadığı için 'probe'
    fallback'i kullanır (gerçek 2s'lik gömülü uyku)."""

    def test_tamam_uyumlu_rapor(self):
        rapor = run_conformance_suite(_session())
        assert set(rapor) == {"watcher_id", "conformant", "checks"}
        assert rapor["watcher_id"] == "dal-watcher"
        assert rapor["conformant"] is True
        assert [(c["id"], c["name"]) for c in rapor["checks"]] == _CHECK_ADLARI
        for c in rapor["checks"]:
            assert set(c) == {"id", "name", "passed", "detail"}
            assert c["passed"] is True
            assert c["detail"]

    def test_c10_probe_fallback_detayı(self):
        rapor = run_conformance_suite(_session())
        c10 = _check_al(rapor, "C10")
        assert c10["passed"]
        # manifest timeout_seconds=0 -> `deadline or 'probe'` + literal "s"
        assert c10["detail"] == "deadline honored (probes contract exercised)"

    def test_c7_kıstırma_detayı(self):
        rapor = run_conformance_suite(_session())
        c7 = _check_al(rapor, "C7")
        assert c7["detail"] == "confidence clamped to 1.0"

    def test_prob_talebişekli(self):
        claim = _probe_claim()
        assert claim.claim_id == "conf-probe"
        assert claim.derived_from == _EID
        assert claim.falsifiable_by == ("watcher",)


# ---------------------------------------------------------------------------
# C1 manifest round-trip
# ---------------------------------------------------------------------------

class _DonmeyenManifest(WatcherManifest):
    """to_dict'e müdahale eder: round-trip bozulur, başka hiçbir şey değişmez."""

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["name"] = "BOZUK"
        return d


class TestC1ManifestDönüşümü:
    """C1 dalları: geçerli manifest round-trip yapar (yukarıdaki sınıfta);
    to_dict'e dışarıdan müdahale edilince from_dict çıktısı orijinalden
    farklılaşır -> AssertionError 'manifest does not round-trip'."""

    def test_c1_geçerli(self):
        rapor = run_conformance_suite(_session())
        assert _check_al(rapor, "C1")["passed"]
        assert _check_al(rapor, "C1")["detail"] == \
            "invariants hold (W1a ban included)"

    def test_c1_dönüşüm_bozuk(self):
        m = _DonmeyenManifest(**{**_manifest().__dict__})
        rapor = run_conformance_suite(_session(
            lambda s, r: ("SUPPORTS", 0.8, "probe"), manifest=m))
        assert _başarısızlar(rapor) == {"C1"}
        assert "round-trip" in _check_al(rapor, "C1")["detail"]


# ---------------------------------------------------------------------------
# C2 tier tavanı
# ---------------------------------------------------------------------------

class _W1aManifest(WatcherManifest):
    """max_tier='W1a' — __post_init__ doğrulaması bilerek atlanır ki tavan
    mekanizmasının kendisi (KeyError yolu) sınanabilsin."""

    def __post_init__(self) -> None:
        pass


class TestC2TierTavanı:
    """C2 dalları: izinli her max_tier aynen çıkar ve W1a ASLA üretilmez;
    W1a'lı bir manifesttte _CEILING_TIER['W1a'] KeyError verir (tavan
    bir kıstırma değil, anahtar-lookuptur) ve _check bunu izole eder."""

    @pytest.mark.parametrize("tier", ["W1b", "W2", "W3"])
    def test_izinli_tierler(self, tier):
        item = run_session(_session(
            lambda s, r: ("SUPPORTS", 0.8, "t"),
            capabilities={"evidence_classes": ("WATCHER_REPORT",),
                          "max_tier": tier, "subscribes_to": ("*",)}),
            _iddia(), "dagı")
        assert item is not None
        assert item.tier == tier
        assert item.tier != "W1a"

    def test_ceiling_dictte_w1a_yok(self):
        from veridict.watchers import _CEILING_TIER
        assert "W1a" not in _CEILING_TIER
        assert set(_CEILING_TIER) == {"W1b", "W2", "W3"}

    def test_c2_w1a_keyerror_izole(self):
        # _W1aManifest __post_init__'i atladığı için max_tier='W1a' geçerlidir;
        # iç _manifest() çağrısı YAPILAMAZ (kendisi ValueError verir).
        base = {**_manifest().__dict__,
                "capabilities": {"evidence_classes": ("WATCHER_REPORT",),
                                 "max_tier": "W1a", "subscribes_to": ("*",)}}
        m = _W1aManifest(**base)
        rapor = run_conformance_suite(_session(
            lambda s, r: ("SUPPORTS", 0.8, "probe"), manifest=m))
        c2 = _check_al(rapor, "C2")
        assert not c2["passed"]
        assert "W1a" in c2["detail"]


# ---------------------------------------------------------------------------
# C3 körlük
# ---------------------------------------------------------------------------

class TestC3Körlük:
    """C3 dalları: fn tam olarak 2 konumsal argüman alır — (summary, ref);
    ref, artifact_path verilince path, verilmezse artifact_digest'tir;
    çok argümanlı çağrı Reddedilir (körlik ihlali); suite'in C3'ü hata
    fırlatan bir fn ile bile geçer (kayıt, orijinal çağrılmadan önce yapılır).

    NOT: C3'ün başarısız dalı (got None / len != 2) public API üzerinden
    erişilemez — run_session her zaman 2 argümanla çağırır; savunma amaçlıdır."""

    def test_ref_path_verilince(self):
        görülen = {}

        def kayıt(summary, ref):
            görülen["args"] = (summary, ref)
            return ("SUPPORTS", 0.8, "kayıt")

        run_session(WatcherSession(_manifest(), kayıt), _iddia(), "dagı",
                    artifact_path="/tmp/dal/dizin")
        assert görülen["args"] == ("dal test summary", "/tmp/dal/dizin")

    def test_ref_path_verilmeyince_digest(self):
        görülen = {}

        def kayıt(summary, ref):
            görülen["args"] = (summary, ref)
            return ("REFUTES", 0.3, "kayıt")

        run_session(WatcherSession(_manifest(), kayıt), _iddia(), "dagı")
        assert görülen["args"] == ("dal test summary", "dagı")

    def test_tam_iki_argümandan_fazlası_red(self):
        def sadece_iki(*args):
            assert len(args) == 2, f"körlik ihlali: {args!r}"
            return ("SUPPORTS", 0.5, "iki")

        item = run_session(WatcherSession(_manifest(), sadece_iki),
                           _iddia(), "dagı", artifact_path="/tmp/dal")
        assert item is not None

    def test_c3_suite_içinde_patlarken_de_geçer(self):
        def patla(summary, ref):
            raise RuntimeError("patla")

        rapor = run_conformance_suite(_session(patla))
        assert _check_al(rapor, "C3")["passed"]
        assert _check_al(rapor, "C3")["detail"] == \
            "inputs: (summary, artifact-reference) only"


# ---------------------------------------------------------------------------
# C4 hata => istisna / C5 None => istisna
# ---------------------------------------------------------------------------

class TestC4Hataİstisna:
    """C4 dalları: Exception alt sınıfı her hata -> None (istisna);
    KeyboardInterrupt/SystemExit (BaseException) YAKALANMAZ ve audit'i
    çökertir — B4 belgesi."""

    @pytest.mark.parametrize("exc", [
        RuntimeError("dal"), ValueError("dal"), OSError("dal"),
        ZeroDivisionError("dal"), TypeError("dal"), MemoryError("dal"),
    ])
    def test_hata_istisna(self, exc):
        def patla(summary, ref):
            raise exc

        assert run_session(WatcherSession(_manifest(), patla),
                           _iddia(), "dagı") is None

    @pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit])
    def test_base_exception_sızar(self, exc):
        def patla(summary, ref):
            raise exc("dal")

        with pytest.raises(exc):
            run_session(WatcherSession(_manifest(), patla), _iddia(), "dagı")

    def test_c4_suite_içinde(self):
        rapor = run_conformance_suite(_session(
            lambda s, r: _fırlat(RuntimeError("probe crash"))))
        assert _check_al(rapor, "C4")["passed"]
        assert _check_al(rapor, "C4")["detail"] == "error → abstain"


class TestC5Noneİstisna:
    """C5 dalı: fn None dönerse kanıt üretilmez."""

    def test_none_istisna(self):
        assert run_session(WatcherSession(_manifest(), lambda s, r: None),
                           _iddia(), "dagı") is None

    @pytest.mark.parametrize("çıktı", [(), ("SUPPORTS",), "SUP", 42, {}])
    def test_yanlış_şekil_de_istisna(self, çıktı):
        """Açılan (unpack) şekil hataları da None'a düşer (C5/C6 sınırı)."""
        assert run_session(WatcherSession(_manifest(), lambda s, r: çıktı),
                           _iddia(), "dagı") is None

    def test_c5_suite_içinde(self):
        rapor = run_conformance_suite(_session(lambda s, r: None))
        assert _check_al(rapor, "C5")["passed"]
        assert _check_al(rapor, "C5")["detail"] == "None → abstain"


# ---------------------------------------------------------------------------
# C6 stance izin listesi
# ---------------------------------------------------------------------------

class TestC6StanceİzinListesi:
    """C6 dalları: SUPPORTS/REFUTES -> kanıt; izin listesi dışı her şey
    (yanlış yazım, harf boyutu, boşluk, None, sayı) -> istisna."""

    @pytest.mark.parametrize("stance", ["SUPPORTS", "REFUTES"])
    def test_izinli_stance(self, stance):
        item = run_session(WatcherSession(
            _manifest(), lambda s, r: (stance, 0.5, "dal")), _iddia(), "dagı")
        assert item is not None
        assert item.stance == stance

    @pytest.mark.parametrize("stance", [
        "MAYBE", "ABSTAIN", "", "SUPPORTS ", " supports", "REFUTES\n",
        "supports", "refutes", "SUPPORTS\0", None, 5, ("SUPPORTS",),
    ])
    def test_izin_dışı_stance(self, stance):
        assert run_session(WatcherSession(
            _manifest(), lambda s, r: (stance, 0.5, "dal")),
            _iddia(), "dagı") is None

    def test_c6_suite_içinde(self):
        rapor = run_conformance_suite(_session(
            lambda s, r: ("MAYBE", 0.5, "x")))
        assert _check_al(rapor, "C6")["passed"]
        assert _check_al(rapor, "C6")["detail"] == "bad stance → abstain"


# ---------------------------------------------------------------------------
# C7 güven kıstırma
# ---------------------------------------------------------------------------

class TestC7GüvenKıstırma:
    """C7 dalları: [0,1] kıstırma — sınır değerleri 0.0/1.0; taşma -0.5->0.0,
    7.3->1.0; str '0.9'->0.9 (float() kabul eder); bool True->1.0/False->0.0;
    nan->1.0, inf->1.0, -inf->0.0 (min/max kıyasla nan yutar)."""

    @pytest.mark.parametrize("girdi,beklenen", [
        (-0.5, 0.0), (0.0, 0.0), (1.0, 1.0), (0.5, 0.5), (2, 1.0), (7.3, 1.0),
        ("0.9", 0.9), (True, 1.0), (False, 0.0),
        (float("inf"), 1.0), (float("-inf"), 0.0), (float("nan"), 1.0),
    ])
    def test_kıstırma(self, girdi, beklenen):
        item = run_session(WatcherSession(
            _manifest(), lambda s, r: ("SUPPORTS", girdi, "k")),
            _iddia(), "dagı")
        assert item is not None
        assert item.confidence == beklenen

    def test_c7_suite_içinde(self):
        rapor = run_conformance_suite(_session())
        assert _check_al(rapor, "C7")["passed"]


# ---------------------------------------------------------------------------
# C8 kanıt şekli
# ---------------------------------------------------------------------------

class TestC8KanıtŞekli:
    """C8 dalları: üretilen kanıt {kind:watcher, family:watcher_id,
    evidence_class: bildirilen, claim_id, identity, version, artifact_ref,
    rationale, evidence_id}; fn istisna yapınca C8 'watcher produced no
    evidence' ile başarısız.

    NOT: producer-şekil başarısız dalları (kind/family yanlış, bildirilmemiş
    sınıf) erişilemez — run_session her zaman bu şekli üretir; savunma amaçlı."""

    def test_şekil_tam(self):
        m = _manifest()
        item = run_session(WatcherSession(m, lambda s, r: ("SUPPORTS", 0.8, "gerekçe")),
                           _iddia(), "dagı")
        assert isinstance(item, EvidenceItem)
        assert item.producer == {"kind": "watcher", "identity": "dal-test",
                                 "version": "0.1.0", "family": "dal-watcher"}
        assert item.evidence_class == "WATCHER_REPORT"
        assert item.claim_id == "dal-claim"
        assert item.artifact_ref == "dagı"
        assert item.rationale == "gerekçe"

    @pytest.mark.parametrize("tier,beklenen", [("W1b", True), ("W2", False),
                                                ("W3", False)])
    def test_determinizm_bayrağı_tier_bağlı(self, tier, beklenen):
        item = run_session(_session(
            lambda s, r: ("SUPPORTS", 0.8, "d"),
            capabilities={"evidence_classes": ("WATCHER_REPORT",),
                          "max_tier": tier, "subscribes_to": ("*",)}),
            _iddia(), "dagı")
        assert item is not None
        assert item.reproducibility["deterministic"] is beklenen
        assert item.reproducibility["rerun_recipe"] is None

    def test_kanıt_id_tuzaklı(self):
        from veridict.utils import sha256_hex
        item = run_session(_session(), _iddia(), "dagı")
        assert item is not None
        beklenen = sha256_hex(f"{EID_SALT}|dal-claim|dal-watcher")[:24]
        assert item.evidence_id == beklenen
        assert len(item.evidence_id) == 24

    def test_kanıt_id_watcher_ailesine_göre_değişir(self):
        a = run_session(_session(lambda s, r: ("SUPPORTS", 0.8, "d")),
                        _iddia(), "dagı")
        b = run_session(_session(lambda s, r: ("SUPPORTS", 0.8, "d"),
                                 watcher_id="baska-watcher"), _iddia(), "dagı")
        assert a is not None and b is not None
        assert a.evidence_id != b.evidence_id

    def test_c8_istisna_yapan_fn(self):
        rapor = run_conformance_suite(_session(lambda s, r: None))
        c8 = _check_al(rapor, "C8")
        assert not c8["passed"]
        assert "no evidence" in c8["detail"]

    def test_c8_geçerli(self):
        rapor = run_conformance_suite(_session())
        assert _check_al(rapor, "C8")["passed"]
        assert _check_al(rapor, "C8")["detail"] == "evidence shape conforms"


# ---------------------------------------------------------------------------
# C9 kayıt defteri
# ---------------------------------------------------------------------------

class _KayıtYapmayanSahteDefter:
    """register() çağrıyı kaydeder ama deftere eklemez — gerçek
    ManifestRegistry.verify_manifest 'not registered' döner, C10'u
    başarısız kılmak için."""

    def __init__(self):
        self.ledger = Ledger()
        self.registered = []

    def register(self, manifest) -> dict:
        self.registered.append(manifest)
        return {}


class TestC9KayıtDefteri:
    """C9 dalları: registry_factory=None -> iç scratch registry (başarılı);
    factory verilirse kullanılır (çağrı sayısı + register); factory'nin
    defteri gerçeğe uymazsa C9 'registry verification failed' ile başarısız."""

    def test_varsayılan_scratch_registry(self):
        rapor = run_conformance_suite(_session())
        c9 = _check_al(rapor, "C9")
        assert c9["passed"]
        assert "scratch registry" in c9["detail"]

    def test_factory_kullanılır(self):
        defterler = []

        def factory():
            led = Ledger()
            ks = KeyStore(led)
            kid = ks.generate_and_enroll("dal-registry")
            reg = ManifestRegistry(led, ks, kid)
            defterler.append(led)
            return reg

        calls = []
        factory_orijinal = factory

        def sayan():
            calls.append(1)
            return factory_orijinal()

        rapor = run_conformance_suite(_session(), registry_factory=sayan)
        assert _check_al(rapor, "C9")["passed"]
        assert len(calls) == 1
        assert len(defterler) == 1
        # scratch registry izole: kayıt o defterde görünür
        assert len(defterler[0].query("watcher.registered")) == 1
        assert defterler[0].query("watcher.registered")[0]["payload"]["manifest"]["watcher_id"] == "dal-watcher"

    def test_factory_doğrulama_başarısız(self):
        sahte = []

        def factory():
            reg = _KayıtYapmayanSahteDefter()
            sahte.append(reg)
            return reg

        rapor = run_conformance_suite(_session(), registry_factory=factory)
        c9 = _check_al(rapor, "C9")
        assert not c9["passed"]
        assert "registry verification failed" in c9["detail"]
        # register gerçekten çağrıldı, ama deftere eklenmedi
        assert len(sahte[0].registered) == 1
        assert len(sahte[0].ledger.entries) == 0

    def test_factory_istisna_verirse_izole(self):
        def factory():
            raise RuntimeError("defter yok")

        rapor = run_conformance_suite(_session(), registry_factory=factory)
        c9 = _check_al(rapor, "C9")
        assert not c9["passed"]
        assert "defter yok" in c9["detail"]


# ---------------------------------------------------------------------------
# C10 kaynak zaman aşımı
# ---------------------------------------------------------------------------

class TestC10KaynakZamanAşımı:
    """C10 dalları: manifest timeout_seconds => aşınca istisna; açık
    timeout_seconds manifest değerini EZER (None ise manifest kullanılır);
    deadline 0/None/eksile => satır-içi (thread havuzu yok).
    C10'un kendi gömülü yavaş fn'i (sleep 2, timeout 1) suite içinde sınanır."""

    def test_açık_deadline_manifesti_ezer(self):
        def yavaş(summary, ref):
            time.sleep(0.3)
            return ("SUPPORTS", 0.8, "geç")

        out = run_session(WatcherSession(_manifest(
            resource_class={"timeout_seconds": 5, "cost_budget": 0,
                            "sandbox_level": "none"}), yavaş),
            _iddia(), "dagı", timeout_seconds=0.1)
        assert out is None                    # 0.1 kazanır, 5 değil

    def test_açık_none_manifesti_kullanır(self):
        def hızlı(summary, ref):
            return ("SUPPORTS", 0.8, "hızlı")

        out = run_session(WatcherSession(_manifest(
            resource_class={"timeout_seconds": 5, "cost_budget": 0,
                            "sandbox_level": "none"}), hızlı),
            _iddia(), "dagı", timeout_seconds=None)
        assert out is not None                # manifest 5'i kullanır

    def test_manifest_deadline_sınırdan_geçer(self):
        def yavaş(summary, ref):
            time.sleep(0.3)
            return ("REFUTES", 0.4, "geç")

        out = run_session(WatcherSession(_manifest(
            resource_class={"timeout_seconds": 0.1, "cost_budget": 0,
                            "sandbox_level": "none"}), yavaş),
            _iddia(), "dagı")
        assert out is None

    @pytest.mark.parametrize("deadline", [0, None, -1])
    def test_sıfır_eksil_deadline_satır_içi(self, deadline):
        """deadline <= 0 => thread havuzu kurulmaz, fn çağıran thread'te."""
        görülen = {}

        def kayıt(summary, ref):
            görülen["thread"] = threading.get_ident()
            return ("SUPPORTS", 0.8, "satır-içi")

        out = run_session(WatcherSession(_manifest(), kayıt),
                          _iddia(), "dagı", timeout_seconds=deadline)
        assert out is not None
        assert görülen["thread"] == threading.get_ident()

    def test_manifest_timeout_antharı_yoksa(self):
        out = run_session(WatcherSession(_manifest(
            resource_class={"cost_budget": 0, "sandbox_level": "none"}),
            lambda s, r: ("SUPPORTS", 0.8, "anahtar yok")),
            _iddia(), "dagı")
        assert out is not None                # .get(...) or 0 -> 0 -> satır-içi

    def test_c10_suite_içinde_zaman_aşımı(self):
        rapor = run_conformance_suite(_session())
        c10 = _check_al(rapor, "C10")
        assert c10["passed"]
        assert "deadline honored" in c10["detail"]


# ---------------------------------------------------------------------------
# C11 transport determinizmi
# ---------------------------------------------------------------------------

class TestC11Determinizm:
    """C11 dalları: aynı girdilerle 3 koşu özdeş kanıt (kit'in SABIT probe
    fn'i ile); her zaman geçer.

    BULGU (B5): C11 determinizmi session.doctrine_fn ile DEĞIL, kit'in kendi
    sabit lambda'ı ile ölçer — yani durumsal/rastgele bir watcher fn'i C11
    tarafından GÖRÜLMEZ. C11 yalnızca transport'un (run_session)
    determinizmini sınar; doctrine fn'inin determinizmi sınanmaz."""

    def test_üç_koşu_özdeş(self):
        for _ in range(3):
            item = run_session(_session(lambda s, r: ("REFUTES", 0.7, "d")),
                               _iddia(), "dagı")
            assert item is not None
            assert (item.stance, item.confidence, item.tier,
                    item.evidence_class) == ("REFUTES", 0.7, "W1b", "WATCHER_REPORT")

    def test_c11_durumsuz_fn_geçer(self):
        rapor = run_conformance_suite(_session())
        c11 = _check_al(rapor, "C11")
        assert c11["passed"]
        assert "deterministic across 3 runs" in c11["detail"]

    def test_c11_durumlu_fn_da_geçer(self):
        """B5: dönen (her çağrıda farklı sonuç veren) bir doctrine fn'i bile
        C11'i geçer — çünkü C11 session'ın fn'ini hiç çağırmaz."""

        def dönen(summary, ref):
            dönen.i = getattr(dönen, "i", 0) + 1
            return ("SUPPORTS" if dönen.i % 2 else "REFUTES", 0.5, "dönen")

        rapor = run_conformance_suite(_session(dönen))
        c11 = _check_al(rapor, "C11")
        assert c11["passed"]
        assert "deterministic across 3 runs" in c11["detail"]
        # ama kanıtın kendisi durumsuzdur — doctrine fn'inin kararsızlığı
        # kanıta yansımaz çünkü C11 kendi fn'ini kullanır
        assert c11["detail"].count("REFUTES") == 1

    def test_c11_geçerli_detay(self):
        rapor = run_conformance_suite(_session(
            lambda s, r: ("REFUTES", 0.7, "deterministic")))
        assert _check_al(rapor, "C11")["passed"]
        assert "deterministic across 3 runs" in _check_al(rapor, "C11")["detail"]


# ---------------------------------------------------------------------------
# C12 kanıt-sınıfı tavanı
# ---------------------------------------------------------------------------

class TestC12KanıtSınıfıTavanı:
    """C12 dalları: üretilen sınıf bildirilen kümede; BOŞ evidence_classes
    bildirilince tavan 'vacuous' geçer — ama o zaman transport üretemez
    (IndexError try dışında — B1) ve C2/C7/C8/C11 düşer."""

    def test_c12_geçerli(self):
        rapor = run_conformance_suite(_session())
        c12 = _check_al(rapor, "C12")
        assert c12["passed"]
        assert c12["detail"] == "class within declared set (WATCHER_REPORT)"

    @pytest.mark.parametrize("sınıf", [
        ("TEST_EXECUTION",), ("FORMAL_PROOF",), ("STATIC_ANALYSIS",),
        ("WATCHER_REPORT", "TEST_EXECUTION"),
    ])
    def test_c12_farklı_bildirilen_sınıflar(self, sınıf):
        item = run_session(_session(
            lambda s, r: ("SUPPORTS", 0.9, "probe"),
            capabilities={"evidence_classes": sınıf, "max_tier": "W1b",
                          "subscribes_to": ("*",)}),
            _iddia(), "dagı")
        assert item is not None
        assert item.evidence_class == sınıf[0]

    def test_c12_boş_bildiri_vacuous(self):
        rapor = run_conformance_suite(_session(
            lambda s, r: ("SUPPORTS", 0.9, "probe"),
            capabilities={"evidence_classes": (), "max_tier": "W1b",
                          "subscribes_to": ("*",)}))
        c12 = _check_al(rapor, "C12")
        assert c12["passed"]
        assert c12["detail"] == "no evidence_classes declared — ceiling vacuous"

    def test_boş_bildiri_transport_uretemez(self):
        """B1: evidence_classes[0] indeksi try bloğu dışında — boş liste
        IndexError verir, _check tarafından izole edilir (abstain değil)."""
        rapor = run_conformance_suite(_session(
            lambda s, r: ("SUPPORTS", 0.9, "probe"),
            capabilities={"evidence_classes": (), "max_tier": "W1b",
                          "subscribes_to": ("*",)}))
        assert _başarısızlar(rapor) >= {"C2", "C7", "C8", "C11"}
        for cid in ("C2", "C7", "C8", "C11"):
            assert "IndexError" in _check_al(rapor, cid)["detail"] or \
                "no evidence" in _check_al(rapor, cid)["detail"]


# ---------------------------------------------------------------------------
# C13 sandbox/bütçe tutarlılığı
# ---------------------------------------------------------------------------

class TestC13KumandaBütçe:
    """C13 dalları: inprocess + bütçe>0 => 'manifest lies' başarısız;
    inprocess + bütçe 0/negatif => geçer (negatif B2 gap'i);
    inprocess dışı her seviye her bütçeyle geçer (B3); sayısal olmayan
    bütçe => ValueError, _check izole eder."""

    @pytest.mark.parametrize("bütçe", [0, 0.0, -1, -100.5])
    def test_inprocess_sıfır_negatif_geçer(self, bütçe):
        rapor = run_conformance_suite(_session(
            lambda s, r: ("SUPPORTS", 0.8, "probe"),
            resource_class={"timeout_seconds": 0, "cost_budget": bütçe,
                            "sandbox_level": "inprocess"}))
        c13 = _check_al(rapor, "C13")
        assert c13["passed"]

    def test_inprocess_pozitif_başarısız(self):
        rapor = run_conformance_suite(_session(
            lambda s, r: ("SUPPORTS", 0.8, "probe"),
            resource_class={"timeout_seconds": 0, "cost_budget": 1,
                            "sandbox_level": "inprocess"}))
        c13 = _check_al(rapor, "C13")
        assert not c13["passed"]
        assert "lies" in c13["detail"]

    @pytest.mark.parametrize("seviye", ["none", "host", "network", "vm"])
    def test_inprocess_dışı_denetlenmez(self, seviye):
        rapor = run_conformance_suite(_session(
            lambda s, r: ("SUPPORTS", 0.8, "probe"),
            resource_class={"timeout_seconds": 0, "cost_budget": 999,
                            "sandbox_level": seviye}))
        assert _check_al(rapor, "C13")["passed"]

    def test_sayısal_olmayan_bütçe_valueerror(self):
        rapor = run_conformance_suite(_session(
            lambda s, r: ("SUPPORTS", 0.8, "probe"),
            resource_class={"timeout_seconds": 0, "cost_budget": "çok para",
                            "sandbox_level": "inprocess"}))
        c13 = _check_al(rapor, "C13")
        assert not c13["passed"]
        assert "ValueError" in c13["detail"]

    def test_resource_class_none_geçer(self):
        rapor = run_conformance_suite(_session(
            lambda s, r: ("SUPPORTS", 0.8, "probe"),
            resource_class={"timeout_seconds": 0, "cost_budget": 0,
                            "sandbox_level": "none"}))
        c13 = _check_al(rapor, "C13")
        assert c13["passed"]
        assert c13["detail"] == "sandbox/budget coherent (none, 0.0)"


# ---------------------------------------------------------------------------
# _check izolasyon çekirdeği
# ---------------------------------------------------------------------------

class TestCheckİzolasyon:
    """_check dalları: Exception -> {passed:False, detail: repr(exc)};
    falsy detail -> 'ok' (None, '', 0); truthy detail olduğu gibi;
    BaseException SIZAR (izolasyon sadece Exception kadardır — B4)."""

    def test_istisna_izole(self):
        r = _check("X", "n", lambda: _fırlat(ValueError("boom")))
        assert r == {"id": "X", "name": "n", "passed": False,
                     "detail": "ValueError('boom')"}

    @pytest.mark.parametrize("detay", [None, "", 0, False, [], ()])
    def test_falsy_detay_ok(self, detay):
        assert _check("X", "n", lambda: detay)["detail"] == "ok"

    @pytest.mark.parametrize("detay", ["detay", 1, True, ["d"], {"a": 1}])
    def test_truthy_detay_kalır(self, detay):
        assert _check("X", "n", lambda: detay)["detail"] == detay

    @pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit])
    def test_base_exception_sızar(self, exc):
        with pytest.raises(exc):
            _check("X", "n", lambda: _fırlat(exc("dal")))


# ---------------------------------------------------------------------------
# modül yüzeyi
# ---------------------------------------------------------------------------

class TestModülYüzeyi:
    """Sabit sözleşmeler: _EID digest'tir; suite modülü import edilebilirdir."""

    def test_eid_sabiti(self):
        assert conformance._EID == "conf-probe-digest"

    def test_hızlı_başarısızlık_conformant_false(self):
        """Tek bir check düşmesi conformant'i False yapar (all() semantiği)."""
        rapor = run_conformance_suite(_session(lambda s, r: None))
        assert rapor["conformant"] is False
        assert _başarısızlar(rapor) == {"C8"}
