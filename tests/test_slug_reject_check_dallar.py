"""Veridict saf-yardimci fonksiyonlar dal-kesen testleri (LEED).

Kural-1: MEVCUT DOSYALARA DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (regex/json/ledger-bellek — dis cagri YOK).
_slug (claim_extractor) + _reject_dupes (ledger) + _check/_probe_claim
(conformance) + _revocation_status (certificate) + _receipt_revoked (receipt)
+ _has_negative_delta (calibration).
"""
import sys

import pytest

sys.path.insert(0, ".")
from veridict.calibration import _has_negative_delta  # noqa: E402
from veridict.certificate import _revocation_status  # noqa: E402
from veridict.claim_extractor import _slug  # noqa: E402
from veridict.conformance import _check, _probe_claim  # noqa: E402
from veridict.ledger import Ledger, _reject_dupes  # noqa: E402
from veridict.receipt import _receipt_revoked  # noqa: E402
from veridict.schemas import ActorRef, Claim  # noqa: E402


def _led(*entries):
    led = Ledger()
    for et, payload in entries:
        led.append(et, ActorRef(kind="system", identity="i", version="1"), payload)
    return led


# == _slug ======================================================================================

@pytest.mark.parametrize("text,expected", [
    ("hello", "hello"),
    ("Hello, World!", "hello-world"),
    ("", ""),
    ("   ", ""),
    ("!!!***", ""),
    ("99 bottles", "99-bottles"),
    ("miXedCaSe", "mixedcase"),
    ("a--b", "a-b"),
    ("tab\tsep", "tab-sep"),
    ("a1b2c3", "a1b2c3"),
    ("one two three four five six seven eight nine ten",
     "one-two-three-four-five-six-seven-eight"),
])
def test_slug_taban(text, expected):
    """ORTAM: [a-z0-9]+ kelimeleri '-'-birlesim, lower(), ILK 8 kelime."""
    assert _slug(text) == expected


@pytest.mark.parametrize("text,expected", [
    ("CAFÉ", "caf"),                 # ASCII-disi harf [a-z0-9] disinda
    ("Éé", ""),                      # tamamen ASCII-disi -> bos
    ("ünïcode test", "n-code-test"), # yalnizca 'n','code','test' ASCII
    ("日本語", ""),                  # CJK -> bos
    ("café", "caf"),
])
def test_slug_ascii_disi(text, expected):
    """ORTAM-OGRENDI: re [a-z0-9] ASCII-tabanli; .lower() sonrasi bile
    ASCII-olmayan harfler ELELENIR — Unicode-kelime sinirlamasinin
    kelime-karakterlerine yansimasi."""
    assert _slug(text) == expected


@pytest.mark.parametrize("text", [
    "hello", "a b c", "x1 y2", "12345", "single",
])
def test_slug_dusuk_kelime_sayisi(text):
    """ORTAM: 8 kelime altinda TAMAMINI korur."""
    words = text.replace("\t", " ").split()
    assert _slug(text) == "-".join(w.lower() for w in words)


@pytest.mark.parametrize("n,expected_n", [(8, 8), (9, 8), (12, 8), (1, 1), (0, 0)])
def test_slug_sekiz_kelime_saptirma(n, expected_n):
    """ORTAM-OGRENDI: words[:8] — 8+ kelime kesilir, tam 8 korunur, 0 kelime bos."""
    text = " ".join(f"w{i}" for i in range(n))
    out = _slug(text)
    parts = out.split("-") if out else []
    assert len(parts) == expected_n


def test_slug_sayi_ve_noktalama():
    """ORTAM: noktalama silinir, rakamlar korunur, coklu-boslik tekleyer."""
    assert _slug("v1.2.3 -- beta!!!") == "v1-2-3-beta"
    assert _slug("a###b") == "a-b"


def test_slug_always_str():
    """ORTAM: cikti herzaman str (None DEGIL, bosken bile)."""
    assert isinstance(_slug(""), str)
    assert isinstance(_slug("x"), str)


# == _reject_dupes ==============================================================================

@pytest.mark.parametrize("pairs,expected", [
    ([], {}),
    ([("a", 1)], {"a": 1}),
    ([("b", 2), ("a", 1)], {"b": 2, "a": 1}),   # sirayi KORUR
    ([("a", 1), ("b", 2), ("c", 3)], {"a": 1, "b": 2, "c": 3}),
    ([("x", "y")], {"x": "y"}),
])
def test_reject_dupes_temiz(pairs, expected):
    """ORTAM: tekrarsiz pairs -> dict (yerlestirme sirasi KORUNUR)."""
    assert _reject_dupes(pairs) == expected


@pytest.mark.parametrize("pairs,key", [
    ([("a", 1), ("a", 2)], "a"),
    ([("a", 1), ("b", 2), ("a", 3)], "a"),
    ([("z", 0), ("z", 1)], "z"),
    ([("dup", 1), ("other", 2), ("dup", 9)], "dup"),
])
def test_reject_dupes_tekrar(pairs, key):
    """ORTAM-OGRENDI: JSON anahtar-tekrari -> ValueError; parser-differential
    (ayni digest iki farkli belge) onlenir — last-wins DEGIL, RED."""
    with pytest.raises(ValueError, match="duplicate JSON key"):
        _reject_dupes(pairs)


def test_reject_dupes_ilk_tekrar_mesaji():
    """ORTAM: hata mesaji anahtari icerir."""
    with pytest.raises(ValueError) as ei:
        _reject_dupes([("k", 1), ("k", 2)])
    assert "'k'" in str(ei.value)


def test_reject_dupes_deger_tipi_serbest():
    """ORTAM: degerler her tip olabilir (dict/list/None)."""
    out = _reject_dupes([("a", {"x": 1}), ("b", [1, 2]), ("c", None)])
    assert out == {"a": {"x": 1}, "b": [1, 2], "c": None}


def test_reject_dupes_bosluk_duyarli():
    """ORTAM: 'a' ile 'a ' FARKLI anahtarlar (bosluk onemli)."""
    assert _reject_dupes([("a", 1), ("a ", 2)]) == {"a": 1, "a ": 2}


# == _check =====================================================================================

@pytest.mark.parametrize("detail", ["ok-string", "", None, 0, 42, {"k": "v"}])
def test_check_basari(detail):
    """ORTAM: fn dondugunde passed=True; detail falsy ise 'ok' metni."""
    out = _check("CID", "name", lambda: detail)
    assert out["id"] == "CID"
    assert out["name"] == "name"
    assert out["passed"] is True
    assert out["detail"] == (detail if detail else "ok")


@pytest.mark.parametrize("exc", [
    ZeroDivisionError("division by zero"), ValueError("bad"),
    RuntimeError("boom"), TypeError("t"), KeyError("missing"),
    IndexError("out of range"), AttributeError("nope"),
    AssertionError("assertion failed"), OSError("io fail"),
])
def test_check_hata_izolasyonu(exc):
    """ORTAM-OGRENDI: fn herhangi bir exception firlatirsa _check YUTAR —
    izolasyon sozlesme: bir crash butun suite'i DEGIL, o kontrolu isaretler.
    detail repr(exc) olarak kaydedilir (sinif+mesaj)."""
    captured = exc

    def fn():
        raise captured
    out = _check("C9", "label", fn)
    assert out["passed"] is False
    assert out["id"] == "C9"
    assert out["name"] == "label"
    assert repr(captured) == out["detail"]
    assert type(captured).__name__ in out["detail"]


def test_check_hata_metni_icerigi():
    """ORTAM: detail, exception'in repr'ini tam tasir."""
    out = _check("X", "y", lambda: (_ for _ in ()).throw(ValueError("specific-msg")))
    assert "specific-msg" in out["detail"]
    assert "ValueError" in out["detail"]


def test_check_systemexit_yayilir():
    """ORTAM-OGRENDI (QUIRK): _check 'except Exception' yakalar — SystemExit
    BaseException alt-sinifu oldugu icin YAYILIR ve suite'i oldurur. Bu
    bilincli-bir-sinir degil, Python istisna-hiyerarsisinin sonucu; normal
    hata-tipleri (Exception) izole edilir, kontrol-sinyalleri degil."""
    with pytest.raises(SystemExit):
        _check("S", "sys", lambda: (_ for _ in ()).throw(SystemExit(1)))


def test_check_keyboardinterrupt_yayilir():
    """ORTAM-OGRENDI: KeyboardInterrupt da BaseException alt-sinifi — yayilir."""
    with pytest.raises(KeyboardInterrupt):
        _check("K", "kbd", lambda: (_ for _ in ()).throw(KeyboardInterrupt()))


def test_check_valueerror_tur_sinifi_da_yakalanir():
    """ORTAM: exception-SINIFI firlatmak da yakalanir (Python otomatik
    ornekler); detail bos-argumanli repr tasir."""
    out = _check("V", "v", lambda: (_ for _ in ()).throw(ValueError))
    assert out["passed"] is False
    assert "ValueError" in out["detail"]


def test_check_geri_ve_ilerle():
    """ORTAM: ayni _check ardisik hata/basari cagrilarinda bagimsiz."""
    calls = []
    fn_ok = lambda: calls.append(1) or "done"
    assert _check("A", "a", fn_ok)["passed"] is True
    assert _check("B", "b", lambda: 1 / 0)["passed"] is False
    assert _check("C", "c", fn_ok)["passed"] is True


def test_check_id_ve_ad_sabit():
    """ORTAM: id/name string olarak birebir saklanir."""
    out = _check("custom-id", "custom-name", lambda: None)
    assert out["id"] == "custom-id"
    assert out["name"] == "custom-name"


# == _probe_claim ===============================================================================

def test_probe_claim_alanlari():
    """ORTAM-ANATOMI: sabit prob-iddia claim'i (conformance kitinin girdisi)."""
    c = _probe_claim()
    assert isinstance(c, Claim)
    assert c.claim_id == "conf-probe"
    assert c.task_id == "conf"
    assert c.subject == "conf"
    assert c.predicate == "conformance-probe"
    assert c.scope == "probe"
    assert c.summary == "conformance probe claim"
    assert c.derived_from == "conf-probe-digest"
    assert c.verifiability == "DOCTRINAL"
    assert c.falsifiable_by == ("watcher",)
    assert c.critical_class is None


def test_probe_claim_deterministik():
    """ORTAM: ayni sabit degerler her cagrida (prob tekrarlanabilir)."""
    a, b = _probe_claim(), _probe_claim()
    assert a.claim_id == b.claim_id
    assert a.summary == b.summary


def test_probe_claim_diger_claim_den_farkli():
    """ORTAM: prob-iddia sabit-ozelliklidir, fabrika-degil (parametre YOK)."""
    import inspect
    assert not list(inspect.signature(_probe_claim).parameters)


# == _revocation_status ==========================================================================

@pytest.mark.parametrize("cert_id", ["", None])
def test_revocation_falsy_id(cert_id):
    """ORTAM: falsy cert_id -> hemen None (sorgu YAPILMAZ)."""
    assert _revocation_status(Ledger(), cert_id) is None


def test_revocation_yok():
    """ORTAM: iptal kaydi yoksa None."""
    led = _led(("certificate.issued", {"cert_id": "c1"}))
    assert _revocation_status(led, "c1") is None


def test_revocation_baska_cert():
    """ORTAM: baska bir cert_id'nin iptali sayilmaz."""
    led = _led(("certificate.revoked", {"cert_id": "other", "reason": "r"}))
    assert _revocation_status(led, "c1") is None


def test_revocation_nedeni_duzenlenmis():
    """ORTAM: reason .strip() ile bicimlenir."""
    led = _led(("certificate.revoked",
                {"cert_id": "c1", "reason": "  key compromised  "}))
    assert _revocation_status(led, "c1") == "key compromised"


@pytest.mark.parametrize("reason", ["", "   "])
def test_revocation_nedeni_yok(reason):
    """ORTAM-OGRENDI: bosaltilmis reason -> 'revoked by issuer (no reason
    recorded)' — iptal kaybi YOK, varsayilan-metni vardir."""
    led = _led(("certificate.revoked", {"cert_id": "c1", "reason": reason}))
    assert _revocation_status(led, "c1") == "revoked by issuer (no reason recorded)"


def test_revocation_none_nedeni_quirk():
    """ORTAM-OGRENDI (QUIRK): reason=None -> AttributeError! '.get('reason','')
    .strip()' zinciri None uzerinde .strip() cagirir. _receipt_revoked ayni
    durumda str(...) sardigi icin 'None' METNI dondurur — bu ASIMETRI
    bilincli-bir-guzellik degil, iki fonksiyonun farkli korumasi. Characterization:
    production'i DEGIL, beklentiyi test'e yazdik (Kural-5)."""
    led = _led(("certificate.revoked", {"cert_id": "c1", "reason": None}))
    with pytest.raises(AttributeError):
        _revocation_status(led, "c1")


def test_revocation_nedeni_yok_key():
    """ORTAM: reason ANAHTARI bile yoksa varsayilan-metin."""
    led = _led(("certificate.revoked", {"cert_id": "c1"}))
    assert _revocation_status(led, "c1") == "revoked by issuer (no reason recorded)"


def test_revocation_ilk_kaynak_kazanir():
    """ORTAM-OGRENDI: coklu iptal kaydinda ILK bulunani doner (append-only:
    ikinci kayit gozardi, idempotent-status)."""
    led = _led(("certificate.revoked", {"cert_id": "c1", "reason": "first"}),
               ("certificate.revoked", {"cert_id": "c1", "reason": "second"}))
    assert _revocation_status(led, "c1") == "first"


def test_revocation_diger_entry_type():
    """ORTAM: yalnizca 'certificate.revoked' taranir."""
    led = _led(("certificate.issued", {"cert_id": "c1"}),
               ("evidence.recorded", {"cert_id": "c1", "reason": "sneaky"}))
    assert _revocation_status(led, "c1") is None


# == _receipt_revoked ============================================================================

def test_receipt_revoked_falsy_id():
    """ORTAM: falsy/None -> None."""
    assert _receipt_revoked(Ledger(), "") is None


def test_receipt_revoked_yok():
    """ORTAM: kayit yoksa None."""
    assert _receipt_revoked(Ledger(), "c1") is None


def test_receipt_revoked_nedeni_duzenlenmis():
    """ORTAM: str(...).strip() bicimleme (certificate'dan farkli: str() sarar)."""
    led = _led(("receipt.revoked", {"cert_id": "c1", "reason": "  revoked  "}))
    assert _receipt_revoked(led, "c1") == "revoked"


def test_receipt_revoked_ilk_kazanir():
    """ORTAM: ilk kayit kazanir (append-only idempotent-status)."""
    led = _led(("receipt.revoked", {"cert_id": "c1", "reason": "a"}),
               ("receipt.revoked", {"cert_id": "c1", "reason": "b"}))
    assert _receipt_revoked(led, "c1") == "a"


def test_receipt_revoked_baska_tur():
    """ORTAM: yalnizca 'receipt.revoked' taranir (certificate.revoked DEGIL)."""
    led = _led(("certificate.revoked", {"cert_id": "c1", "reason": "cert-side"}))
    assert _receipt_revoked(led, "c1") is None


def test_receipt_revoked_nedeni_yok():
    """ORTAM: bos reason -> varsayilan-metin."""
    led = _led(("receipt.revoked", {"cert_id": "c1", "reason": ""}))
    assert _receipt_revoked(led, "c1") == "revoked by issuer (no reason recorded)"


def test_receipt_revoked_none_nedeni_str_sarar():
    """ORTAM-OGRENDI (QUIRK-ASIMETRI): receipt str(...) sardigi icin
    reason=None -> 'None' METNI; certificate ayni girdide AttributeError
    firlatir. str(None)='None' → .strip()='None'. Characterization testi."""
    led = _led(("receipt.revoked", {"cert_id": "c1", "reason": None}))
    assert _receipt_revoked(led, "c1") == "None"


# == _has_negative_delta =========================================================================

def test_has_negative_delta_bos():
    """ORTAM: calibration.updated yoksa False."""
    assert _has_negative_delta(Ledger(), "p1") is False


def test_has_negative_delta_eslesme_yok():
    """ORTAM: baska producer'in negatif-deltasi sayilmaz."""
    led = _led(("calibration.updated",
                {"producer_identity": "other", "delta": -0.1, "reason": "r",
                 "claim_id": "c"}))
    assert _has_negative_delta(led, "p1") is False


@pytest.mark.parametrize("delta", [-0.1, -0.5, -1.0, -0.001])
def test_has_negative_delta_negatif(delta):
    """ORTAM: herhangi bir negatif delta True."""
    led = _led(("calibration.updated",
                {"producer_identity": "p1", "delta": delta, "reason": "r",
                 "claim_id": "c"}))
    assert _has_negative_delta(led, "p1") is True


@pytest.mark.parametrize("delta", [0.0, 0.05, 0.1, 1.0])
def test_has_negative_delta_negatif_degil(delta):
    """ORTAM: sifir/pozitif delta True yapmaz (yakin-gecmis-temiz)."""
    led = _led(("calibration.updated",
                {"producer_identity": "p1", "delta": delta, "reason": "r",
                 "claim_id": "c"}))
    assert _has_negative_delta(led, "p1") is False


def test_has_negative_delta_rehab_sonrasi_hala_true():
    """ORTAM-OGRENDI: negatif SONRASI +0.05 rehab gelse bile onceki negatif
    hala listede — any() gecmisi unutmaz (rehab factor'i ayri hesaplanir)."""
    led = _led(("calibration.updated",
                {"producer_identity": "p1", "delta": -0.1, "reason": "r",
                 "claim_id": "c"}),
               ("calibration.updated",
                {"producer_identity": "p1", "delta": 0.05,
                 "reason": "rehab", "claim_id": "c"}))
    assert _has_negative_delta(led, "p1") is True


def test_has_negative_delta_sadece_pozitif():
    """ORTAM: yalnizca rehab gecmisi -> False."""
    led = _led(("calibration.updated",
                {"producer_identity": "p1", "delta": 0.05, "reason": "rehab",
                 "claim_id": "c"}))
    assert _has_negative_delta(led, "p1") is False


def test_has_negative_delta_baska_entry_tur():
    """ORTAM: yalnizca 'calibration.updated' taranir."""
    led = _led(("evidence.recorded",
                {"producer_identity": "p1", "delta": -5.0}))
    assert _has_negative_delta(led, "p1") is False


def test_has_negative_delta_eksik_alan():
    """ORTAM-OGRENDI: payload'da producer_identity yoksa KeyError —
    .get() DEGIL dogrudan ['producer_identity'] erisimi (fail-loud)."""
    led = _led(("calibration.updated", {"delta": -0.1, "claim_id": "c"}))
    with pytest.raises(KeyError):
        _has_negative_delta(led, "p1")


def test_has_negative_delta_coklu_producer_karisik():
    """ORTAM: karisik listede hedef producer'in negatif deltasi bulunur."""
    led = _led(("calibration.updated",
                {"producer_identity": "p2", "delta": -0.1, "reason": "r",
                 "claim_id": "c"}),
               ("calibration.updated",
                {"producer_identity": "p1", "delta": 0.05, "reason": "r",
                 "claim_id": "c"}),
               ("calibration.updated",
                {"producer_identity": "p1", "delta": -0.1, "reason": "r",
                 "claim_id": "c2"}))
    assert _has_negative_delta(led, "p1") is True
    assert _has_negative_delta(led, "p2") is True
    assert _has_negative_delta(led, "p3") is False
