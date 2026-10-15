"""Dal-kesen (branch-cutting) testler: veridict/export.py

Kapsanan public API:
  * STATEMENT_TYPE / VSA_PREDICATE_TYPE / CERT_EXTENSION_FIELD / VERIFIER_ID
    / SPDX_CONTEXT / SPDX_SPEC_VERSION (modül sabitleri)
  * _canonical(obj)                       — kanonik JSON bayt (özetlerin temeli;
    private ama her özetin girdisi olduğu için doğrudan test edilir)
  * _veridict_version()                   — dürüst sürüm probe'u (private)
  * to_vsa(cert, ledger_entries, *, verifier_version=None)
  * dsse_envelope(statement, private_key_pem, key_id)
  * dsse_verify(envelope, public_key_pem)
  * _spdx_ts(iso)                         — mikro-saniye -> saniye Z (private)
  * to_spdx(cert, ledger_entries, *, anchor=None)

DAL LİSTESİ:
  _canonical: sort_keys + compact separators; bytes döner; anahtar sırası
    sonucu değiştirmez; iç-içe dict'ler de sıralanır; boşluk içermez
  _veridict_version: kurulu dist ("veridict-standard" önce, sonra "veridict")
    bulunursa sürüm; ikisi de yoksa "0.5.0+source" fallback'i; ilk isim
    kazanır (kısa-devre)
  to_vsa: subject'inde artifact_digest yoksa / boşsa -> ValueError;
    certificate.issued girdisi yoksa -> ValueError (cert_id mesajda);
    farklı cert_id'li girdi -> ValueError; farklı entry_type -> ValueError;
    risk_level "low" -> PASSED; medium/high/eksik/"LOW" -> FAILED (tam
    eşleşme); verifier_version açık vs None; timeVerified == issued["ts"];
    resourceUri; policy uri + özeti; policy_ref yoksa "default";
    inputAttestations uri + cert özeti; verifiedLevels []; dependencyLevels
    {}; slsaVersion "1.2"; subject task_id yoksa "unknown"; extension alanı
    11 cert alanını taşır (None'lar korunur)
  dsse_envelope/dsse_verify: geçerli round-trip -> True; başka anahtar ->
    False; değiştirilmiş payload -> False; değiştirilmiş payloadType ->
    False; eksik payload -> False; eksik signatures -> False; boş
    signatures -> False; eksik sig -> False; "!!!" payload sessizce b''
    çözülür -> False; payload canonical'a eşit
  _spdx_ts: mikro-saniyeli ISO -> saniye Z; tz-naive -> UTC kabul; offsetli
    -> UTC'ye dönüştür; .999999 kırpılır (yuvarlanmaz)
  to_spdx: digest yok -> ValueError; issued yok -> ValueError; @context;
    CreationInfo (created == _spdx_ts, createdBy); SoftwareAgent;
    Organization (actor_identity; eksikse "unknown-actor"); License
    NOASSERTION; ai_AIPackage (name/downloadLocation/packageVersion/
    primaryPurpose/releaseTime/suppliedBy/verifiedUsing/
    ai_informationAboutApplication/ai_limitation); task_id yoksa "unknown";
    scope_limits "; " ile birleşir; boş/None -> "no scope limits recorded";
    externalRefs: anchorsiz 2; certificationReport + cert özeti; policy;
    anchor dolu -> 3. (server/uuid/logIndex); anchor eksik rekor ->
    öntanımlılar; claim başına annotation; evidence annotation'ları
    (producer dict -> identity; producer str -> kendisi; defterde olmayan
    evidence atlanır); jury_composition families -> annotation;
    profileConformance/rootElement/element listesi; hasDeclaredLicense /
    hasConcludedLicense ilişkileri

BULGULAR (production koduna DOKUNULMADI — burada belgelendi):
  B1: dsse_verify yalnızca (InvalidSignature, KeyError, IndexError) yakalar
      — bozuk DOLU/şifreli base64 (örn. "A") binascii.Error (ValueError
      alt sınıfı) FIRLATIR, False DÖNDÜRMEZ. bool döndürme sözleşmesi
      kırıldığı için tüketici try/wrap yapmak zorunda.
  B2: to_spdx'te jury_composition boş/None families ama dolu dict ise
      `cert["jury_composition"]` fallback'i DICT ANAHTARLARI üzerinde
      dolaşır → "jury families: families" gibi anlamsız bir annotation
      üretilir (boş liste dürüstçe belirtilmez).
  B3: to_spdx'te jury_composition bir LİSTE ise (ledger/JSON'dan gelebilir)
      `.get` AttributeError fırlatır — `or` fallback'i listeler için
      ulaşılamaz (ölü kod). Üretim her zaman {"families": [...]} yazıyor
      (certificate.py:100) ama from_dict/uzak JSON bu garantiyi taşımaz.
  B4: to_vsa/to_spdx issued-girdi eşleşmesi `payload.cert_id == cert_id`
      ile; iki tarafta da cert_id YOKSA None==None EŞLEŞİR — cert_id'siz
      bir cert, içinde cert_id bulunmayan herhangi bir issued girdisiyle
      eşleşip "veridict:cert/None" URI'siyle projeksiyon üretir.
  B5: issued girdisinin payload'u dict DEĞİLse (string vb.)
      `e.get("payload", {}).get(...)` AttributeError fırlatır —
      reddetmek (ValueError) yerine çöker.
  B6: _spdx_ts ISO-olmayan string alırsa ValueError yayılır (to_spdx
      içinden) — zaman damgası bozuksa projeksiyon reddetmez, çöker.
"""
from __future__ import annotations

import base64
import binascii

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from veridict.export import (
    CERT_EXTENSION_FIELD,
    SPDX_CONTEXT,
    SPDX_SPEC_VERSION,
    STATEMENT_TYPE,
    VERIFIER_ID,
    VSA_PREDICATE_TYPE,
    _canonical,
    _spdx_ts,
    _veridict_version,
    dsse_envelope,
    dsse_verify,
    to_spdx,
    to_vsa,
)
from veridict.utils import sha256_hex

TS = "2026-01-02T03:04:05.123456+00:00"
TS_SANIYE = "2026-01-02T03:04:05Z"


# ---------------------------------------------------------------- helpers ----

def _anahtar_cifti() -> tuple[str, str]:
    """Bellek-içi Ed25519 anahtar çifti (ağ/dosya YOK)."""
    priv = Ed25519PrivateKey.generate()
    pem_priv = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                  NoEncryption()).decode()
    pem_pub = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    return pem_priv, pem_pub


def _sertifika(**kw) -> dict:
    cert = {
        "cert_id": "cid-1",
        "risk_level": "low",
        "score": 0.9,
        "policy_mode": "CERTIFICATE",
        "disclosure_level": "full",
        "divergence_summary": "uyumsuzluk yok",
        "jury_composition": {"families": ["fa", "fb"]},
        "scope_limits": ["sınır-a", "sınır-b"],
        "ledger_anchor": "anchor-1",
        "verify_instructions": "veridict verify --anchor anchor-1",
        "policy_ref": {"policy_id": "pol-1"},
        "subject": {"task_id": "t-1", "actor_identity": "aktör-1",
                    "artifact_digest": "digest-abc"},
        "claims": [{"claim_id": "cl-1", "verdict_value": "VERIFIED",
                    "divergence": 0.0, "evidence_ids": ["ev-1", "ev-yok"]}],
    }
    cert.update(kw)
    return cert


def _defter(ts: str = TS, cert_id: str = "cid-1", extra=None) -> list[dict]:
    girdiler = [{"entry_type": "certificate.issued", "ts": ts,
                 "payload": {"cert_id": cert_id}}]
    if extra:
        girdiler.extend(extra)
    return girdiler


def _spdx_eleman(doc: dict, sonek: str) -> dict:
    base = "https://veridict.dev/spdx/cid-1"
    for g in doc["@graph"]:
        if g.get("spdxId") == f"{base}#{sonek}":
            return g
    raise KeyError(f"eleman bulunamadı: {sonek}")


def _annotationlar(doc: dict) -> list[dict]:
    return [g for g in doc["@graph"] if g.get("type") == "Annotation"]


# ================================================================ _canonical =

class TestCanonical:
    """_canonical: kanonik JSON bayt üretimi."""

    def test_sorted_ve_compact(self):
        assert _canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_bytes_donuyor(self):
        assert isinstance(_canonical({"a": 1}), bytes)

    def test_anahtar_sirasi_onemsiz(self):
        assert _canonical({"a": 1, "b": 2}) == _canonical({"b": 2, "a": 1})

    def test_ic_ice_dict_siralama(self):
        out = _canonical({"d": {"z": 1, "a": 2}, "n": 0})
        assert out == b'{"d":{"a":2,"z":1},"n":0}'

    def test_bosluk_icermez(self):
        assert b'{"a": 1}' not in _canonical({"a": 1})

    def test_farkli_icerik_farkli_bayt(self):
        assert _canonical({"a": 1}) != _canonical({"a": 2})

    def test_unicode_korunur(self):
        import json
        beklenen = json.dumps({"k": "ğ"}, sort_keys=True,
                              separators=(",", ":")).encode()
        assert _canonical({"k": "ğ"}) == beklenen


# ======================================================== _veridict_version ==

class TestVeridictVersion:
    """_veridict_version: iki-isimli probe + fallback (BULGU kaynağı)."""

    def test_kurulu_dist_donuyor(self):
        v = _veridict_version()
        assert isinstance(v, str) and v != ""

    def test_birinci_isim_kazanir(self, monkeypatch):
        from importlib.metadata import PackageNotFoundError

        def sahte(ad):
            if ad == "veridict-standard":
                return "1.2.3"
            raise PackageNotFoundError(ad)

        monkeypatch.setattr("importlib.metadata.version", sahte)
        assert _veridict_version() == "1.2.3"

    def test_birinci_yoksa_ikinci(self, monkeypatch):
        from importlib.metadata import PackageNotFoundError

        def sahte(ad):
            if ad == "veridict":
                return "9.9.9"
            raise PackageNotFoundError(ad)

        monkeypatch.setattr("importlib.metadata.version", sahte)
        assert _veridict_version() == "9.9.9"

    def test_ikisi_yoksa_fallback(self, monkeypatch):
        from importlib.metadata import PackageNotFoundError

        def sahte(ad):
            raise PackageNotFoundError(ad)

        monkeypatch.setattr("importlib.metadata.version", sahte)
        assert _veridict_version() == "0.5.0+source"


# ========================================================= to_vsa: reddetme =

class TestToVsaReddetmeler:
    """to_vsa: dürüst projeksiyonun reddedildiğü dallar."""

    @pytest.mark.parametrize("subject", [
        None, {}, {"task_id": "t"}, {"artifact_digest": ""},
    ])
    def test_digest_yoksa_value_error(self, subject):
        cert = _sertifika()
        cert["subject"] = subject
        with pytest.raises(ValueError, match="artifact_digest"):
            to_vsa(cert, _defter())

    def test_issued_girdisi_yoksa_value_error(self):
        with pytest.raises(ValueError, match="certificate.issued"):
            to_vsa(_sertifika(), [])

    def test_issued_girdisi_farkli_cert_id_ise_value_error(self):
        with pytest.raises(ValueError, match="cid-1"):
            to_vsa(_sertifika(), _defter(cert_id="baska"))

    def test_entry_type_farkli_ise_value_error(self):
        girdi = [{"entry_type": "certificate.revoked", "ts": TS,
                  "payload": {"cert_id": "cid-1"}}]
        with pytest.raises(ValueError):
            to_vsa(_sertifika(), girdi)

    def test_cert_id_olmadan_unattributed_govese_eslesir(self):
        """BULGU B4 (DUZELTILDI VERIDICT-EXP-B4): iki tarafta da cert_id yoksa
        None==None eşleşir; URI eskiden 'veridict:cert/None' sentezliyordu —
        artık policy_id'nin 'default'-ön-koşulunun aynısı 'unattributed'."""
        cert = _sertifika()
        cert.pop("cert_id")
        girdi = [{"entry_type": "certificate.issued", "ts": TS, "payload": {}}]
        vsa = to_vsa(cert, girdi)
        assert vsa["predicate"]["inputAttestations"][0]["uri"] \
            == "veridict:cert/unattributed"

    def test_payload_dict_degilse_attribute_error(self):
        """BULGU B5: string payload .get'i çökerür (ValueError değil)."""
        girdi = [{"entry_type": "certificate.issued", "ts": TS,
                  "payload": "string!"}]
        with pytest.raises(AttributeError):
            to_vsa(_sertifika(), girdi)


# ========================================================= to_vsa: başarı ===

class TestToVsaBasarili:
    """to_vsa: başarı dalı ve alan dürüstlüğü."""

    def test_statement_iskeleti(self):
        s = to_vsa(_sertifika(), _defter())
        assert s["_type"] == STATEMENT_TYPE
        assert s["predicateType"] == VSA_PREDICATE_TYPE
        assert s["subject"] == [{"name": "veridict:task/t-1",
                                 "digest": {"sha256": "digest-abc"}}]

    def test_task_id_yoksa_unknown(self):
        cert = _sertifika()
        cert["subject"] = {"actor_identity": "a", "artifact_digest": "d"}
        s = to_vsa(cert, _defter())
        assert s["subject"][0]["name"] == "veridict:task/unknown"

    @pytest.mark.parametrize("risk, beklenen", [
        ("low", "PASSED"),
        ("medium", "FAILED"),
        ("high", "FAILED"),
        ("LOW", "FAILED"),      # tam eşleşme (büyük-küçük duyarlı)
        ("critical", "FAILED"),
    ])
    def test_verification_result(self, risk, beklenen):
        cert = _sertifika(risk_level=risk)
        assert to_vsa(cert, _defter())["predicate"]["verificationResult"] == beklenen

    def test_risk_level_yoksa_failed(self):
        cert = _sertifika()
        cert.pop("risk_level")
        assert to_vsa(cert, _defter())["predicate"]["verificationResult"] == "FAILED"

    def test_time_verified_issued_ts_denir(self):
        s = to_vsa(_sertifika(), _defter(ts="2027-05-06T07:08:09.5+00:00"))
        assert s["predicate"]["timeVerified"] == "2027-05-06T07:08:09.5+00:00"

    def test_resource_uri(self):
        s = to_vsa(_sertifika(), _defter())
        assert s["predicate"]["resourceUri"] == "veridict:artifact/sha256:digest-abc"

    def test_policy_uri_ve_ozeti(self):
        s = to_vsa(_sertifika(), _defter())
        pol = s["predicate"]["policy"]
        assert pol["uri"] == "veridict:policy/pol-1"
        assert pol["digest"]["sha256"] == sha256_hex(_canonical({"policy_id": "pol-1"}))

    def test_policy_ref_yoksa_default(self):
        cert = _sertifika()
        cert["policy_ref"] = None
        pol = to_vsa(cert, _defter())["predicate"]["policy"]
        assert pol["uri"] == "veridict:policy/default"
        assert pol["digest"]["sha256"] == sha256_hex(_canonical({}))

    def test_input_attestations_cert_ozeti(self):
        cert = _sertifika()
        s = to_vsa(cert, _defter())
        ia = s["predicate"]["inputAttestations"][0]
        assert ia["uri"] == "veridict:cert/cid-1"
        assert ia["digest"]["sha256"] == sha256_hex(_canonical(cert))

    def test_slsa_seviyeleri_bos_durur(self):
        p = to_vsa(_sertifika(), _defter())["predicate"]
        assert p["verifiedLevels"] == []
        assert p["dependencyLevels"] == {}
        assert p["slsaVersion"] == "1.2"

    def test_verifier_id_ve_surum(self):
        p = to_vsa(_sertifika(), _defter())["predicate"]
        assert p["verifier"]["id"] == VERIFIER_ID
        assert p["verifier"]["version"]["veridict"] == _veridict_version()

    def test_verifier_version_acik_verilir(self):
        p = to_vsa(_sertifika(), _defter(),
                   verifier_version="9.9-test")["predicate"]
        assert p["verifier"]["version"]["veridict"] == "9.9-test"

    def test_extension_alani_cert_alanlarini_tasir(self):
        cert = _sertifika()
        ext = to_vsa(cert, _defter())["predicate"][CERT_EXTENSION_FIELD]
        assert ext["cert_id"] == "cid-1"
        assert ext["task_id"] == "t-1"
        assert ext["actor_identity"] == "aktör-1"
        assert ext["risk_level"] == "low"
        assert ext["score"] == 0.9
        assert ext["policy_mode"] == "CERTIFICATE"
        assert ext["disclosure_level"] == "full"
        assert ext["divergence_summary"] == "uyumsuzluk yok"
        assert ext["jury_composition"] == {"families": ["fa", "fb"]}
        assert ext["scope_limits"] == ["sınır-a", "sınır-b"]
        assert ext["ledger_anchor"] == "anchor-1"
        assert ext["verify_instructions"] == "veridict verify --anchor anchor-1"

    def test_extension_none_degerleri_korur(self):
        cert = _sertifika(risk_level=None, score=None, divergence_summary=None,
                          scope_limits=None, jury_composition=None,
                          ledger_anchor=None, verify_instructions=None)
        ext = to_vsa(cert, _defter())["predicate"][CERT_EXTENSION_FIELD]
        for k in ("risk_level", "score", "divergence_summary", "scope_limits",
                  "jury_composition", "ledger_anchor", "verify_instructions"):
            assert ext[k] is None

    def test_coklu_girdi_arasindan_eslesen_bulunur(self):
        extra = [
            {"entry_type": "certificate.issued", "ts": "2020-01-01T00:00:00+00:00",
             "payload": {"cert_id": "cid-2"}},
            {"entry_type": "evidence.recorded",
             "payload": {"evidence_id": "ev-1"}},
        ]
        s = to_vsa(_sertifika(), _defter(extra=extra))
        assert s["predicate"]["timeVerified"] == TS


# ================================================================ DSSE ======

class TestDsseZarfi:
    """dsse_envelope / dsse_verify: imzalama + doğrulama dalları."""

    def test_round_trip_gecerli(self):
        priv, pub = _anahtar_cifti()
        env = dsse_envelope({"a": 1, "b": [2, 3]}, priv, "kid-1")
        assert env["payloadType"] == "application/vnd.in-toto+json"
        assert env["signatures"][0]["keyid"] == "kid-1"
        assert env["payload"] == base64.b64encode(
            _canonical({"a": 1, "b": [2, 3]})).decode()
        assert dsse_verify(env, pub) is True

    def test_baska_anahtar_false(self):
        priv, pub = _anahtar_cifti()
        _, yabanci = _anahtar_cifti()
        env = dsse_envelope({"a": 1}, priv, "kid-1")
        assert dsse_verify(env, yabanci) is False

    def test_degistirilmis_payload_false(self):
        priv, pub = _anahtar_cifti()
        env = dsse_envelope({"a": 1}, priv, "kid-1")
        govde = base64.b64decode(env["payload"])
        env["payload"] = base64.b64encode(govde + b"x").decode()
        assert dsse_verify(env, pub) is False

    def test_degistirilmis_payload_type_false(self):
        priv, pub = _anahtar_cifti()
        env = dsse_envelope({"a": 1}, priv, "kid-1")
        env["payloadType"] = "application/baska"
        assert dsse_verify(env, pub) is False

    def test_payload_yoksa_false(self):
        priv, pub = _anahtar_cifti()
        env = dsse_envelope({"a": 1}, priv, "kid-1")
        del env["payload"]
        assert dsse_verify(env, pub) is False

    def test_signatures_yoksa_false(self):
        priv, pub = _anahtar_cifti()
        env = dsse_envelope({"a": 1}, priv, "kid-1")
        del env["signatures"]
        assert dsse_verify(env, pub) is False

    def test_bos_signatures_false(self):
        priv, pub = _anahtar_cifti()
        env = dsse_envelope({"a": 1}, priv, "kid-1")
        env["signatures"] = []
        assert dsse_verify(env, pub) is False

    def test_sig_anahtari_yoksa_false(self):
        priv, pub = _anahtar_cifti()
        env = dsse_envelope({"a": 1}, priv, "kid-1")
        env["signatures"][0] = {"keyid": "kid-1"}
        assert dsse_verify(env, pub) is False

    def test_gecersiz_karakterler_sessizce_bos_cozulur(self):
        """b64decode validate=False: '!!!' -> b'' -> InvalidSignature."""
        priv, pub = _anahtar_cifti()
        env = dsse_envelope({"a": 1}, priv, "kid-1")
        env["payload"] = "!!!"
        assert dsse_verify(env, pub) is False

    def test_kotu_base64_payload_reddedilir(self):
        """BULGU B1 (DUZELTILDI VERIDICT-EXP-B1): 'A' geçersiz dolama eskiden
        binascii.Error-yayıyordu — verify sözleşmesi bool'dur (her-başarısızlık
        False, çağıran doğrulamayı ayırt-etmez)."""
        priv, pub = _anahtar_cifti()
        env = dsse_envelope({"a": 1}, priv, "kid-1")
        env["payload"] = "A"
        assert dsse_verify(env, pub) is False

    def test_kotu_base64_sig_reddedilir(self):
        """BULGU B1 (DUZELTILDI): imzada kötü base64 -> eskiden fırlatır."""
        priv, pub = _anahtar_cifti()
        env = dsse_envelope({"a": 1}, priv, "kid-1")
        env["signatures"][0]["sig"] = "A"
        assert dsse_verify(env, pub) is False


# =============================================================== _spdx_ts ===

class TestSpdxTs:
    """_spdx_ts: mikro-saniye → saniye Z dönüşümü."""

    @pytest.mark.parametrize("iso, beklenen", [
        ("2026-01-02T03:04:05.123456+00:00", "2026-01-02T03:04:05Z"),
        ("2026-01-02T03:04:05.999999+00:00", "2026-01-02T03:04:05Z"),  # kırpılır
        ("2026-01-02T03:04:05", "2026-01-02T03:04:05Z"),               # naive -> UTC
        ("2026-01-02T05:04:05+02:00", "2026-01-02T03:04:05Z"),         # offset
        ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z"),
        ("2026-06-15T23:59:59.5-05:00", "2026-06-16T04:59:59Z"),
    ])
    def test_saniye_kesinliginde_z(self, iso, beklenen):
        assert _spdx_ts(iso) == beklenen

    def test_kotu_string_value_error(self):
        """BULGU B6: ISO-olmayan string ValueError yayılır."""
        with pytest.raises(ValueError):
            _spdx_ts("not-a-timestamp")


# ========================================================= to_spdx reddetme =

class TestToSpdxReddetmeler:
    """to_spdx: aynı reddetme kuralları."""

    @pytest.mark.parametrize("subject", [None, {}, {"task_id": "t"}])
    def test_digest_yoksa_value_error(self, subject):
        cert = _sertifika()
        cert["subject"] = subject
        with pytest.raises(ValueError, match="artifact_digest"):
            to_spdx(cert, _defter())

    def test_issued_girdisi_yoksa_value_error(self):
        with pytest.raises(ValueError, match="certificate.issued"):
            to_spdx(_sertifika(), [])


# ========================================================= to_spdx başarı ===

class TestToSpdxYapi:
    """to_spdx: belke iskeleti ve semantic'ler."""

    def test_context_ve_graph(self):
        doc = to_spdx(_sertifika(), _defter())
        assert doc["@context"] == SPDX_CONTEXT
        assert "@graph" in doc and len(doc["@graph"]) > 0

    def test_creation_info(self):
        doc = to_spdx(_sertifika(), _defter())
        ci = doc["@graph"][0]
        assert ci["@id"] == "_:ci"
        assert ci["type"] == "CreationInfo"
        assert ci["specVersion"] == SPDX_SPEC_VERSION
        assert ci["created"] == TS_SANIYE
        base = "https://veridict.dev/spdx/cid-1"
        assert ci["createdBy"] == [f"{base}#veridict-agent", f"{base}#actor"]
        assert "deterministic projection" in ci["comment"]

    def test_agent_ve_actor(self):
        doc = to_spdx(_sertifika(), _defter())
        assert _spdx_eleman(doc, "veridict-agent")["name"].startswith("veridict ")
        aktor = _spdx_eleman(doc, "actor")
        assert aktor["type"] == "Organization"
        assert aktor["name"] == "aktör-1"
        assert "self-reported" in aktor["comment"]

    def test_actor_identity_yoksa_unknown(self):
        cert = _sertifika()
        cert["subject"] = {"task_id": "t-1", "artifact_digest": "d"}
        doc = to_spdx(cert, _defter())
        assert _spdx_eleman(doc, "actor")["name"] == "unknown-actor"

    def test_lisans_noassertion(self):
        doc = to_spdx(_sertifika(), _defter())
        lic = _spdx_eleman(doc, "license")
        assert lic["type"] == "simplelicensing_LicenseExpression"
        assert lic["simplelicensing_licenseExpression"] == "NOASSERTION"
        assert lic["name"] == "NOASSERTION"

    def test_ai_paket_alanlari(self):
        doc = to_spdx(_sertifika(), _defter())
        pkg = _spdx_eleman(doc, "pkg")
        base = "https://veridict.dev/spdx/cid-1"
        assert pkg["type"] == "ai_AIPackage"
        assert pkg["name"] == "veridict-audit:t-1"
        assert pkg["software_downloadLocation"] == "NOASSERTION"
        assert pkg["software_packageVersion"] == "NOASSERTION"
        assert pkg["software_primaryPurpose"] == "other"
        assert pkg["releaseTime"] == TS_SANIYE
        assert pkg["suppliedBy"] == f"{base}#actor"
        assert pkg["verifiedUsing"] == [{"type": "Hash", "algorithm": "sha256",
                                         "hashValue": "digest-abc"}]
        assert "ai_informationAboutApplication" in pkg
        assert pkg["ai_limitation"] == "sınır-a; sınır-b"

    def test_task_id_yoksa_unknown(self):
        cert = _sertifika()
        cert["subject"] = {"actor_identity": "a", "artifact_digest": "d"}
        doc = to_spdx(cert, _defter())
        assert _spdx_eleman(doc, "pkg")["name"] == "veridict-audit:unknown"

    @pytest.mark.parametrize("sinirlar, beklenen", [
        (["x", "y"], "x; y"),
        ([], "no scope limits recorded"),
        (None, "no scope limits recorded"),
    ])
    def test_ai_limitation_sinirlar(self, sinirlar, beklenen):
        doc = to_spdx(_sertifika(scope_limits=sinirlar), _defter())
        assert _spdx_eleman(doc, "pkg")["ai_limitation"] == beklenen

    def test_external_ref_sayisi_anchorsiz(self):
        pkg = _spdx_eleman(to_spdx(_sertifika(), _defter()), "pkg")
        assert len(pkg["externalRef"]) == 2

    def test_certification_report_ref(self):
        cert = _sertifika()
        pkg = _spdx_eleman(to_spdx(cert, _defter()), "pkg")
        r0 = pkg["externalRef"][0]
        assert r0["externalRefType"] == "certificationReport"
        assert r0["locator"] == ["veridict:cert/cid-1"]
        assert sha256_hex(_canonical(cert)) in r0["comment"]

    def test_policy_ref(self):
        pkg = _spdx_eleman(to_spdx(_sertifika(), _defter()), "pkg")
        r1 = pkg["externalRef"][1]
        assert r1["externalRefType"] == "other"
        assert r1["locator"] == ["veridict:policy/pol-1"]
        assert "Policy declaration" in r1["comment"]

    def test_anchor_dolu_ise_ucuncu_ref(self):
        anchor = {"rekor": {"server": "https://rekor.example",
                            "uuid": "uuid-9", "entry": {"logIndex": 7}}}
        pkg = _spdx_eleman(to_spdx(_sertifika(), _defter(), anchor=anchor), "pkg")
        assert len(pkg["externalRef"]) == 3
        r2 = pkg["externalRef"][2]
        assert r2["locator"] == ["https://rekor.example/api/v1/log/entries/uuid-9"]
        assert "logIndex 7" in r2["comment"]

    @pytest.mark.parametrize("anchor, beklenen", [
        ({"rekor": {}}, None),
        ({"rekor": {"uuid": "u1"}},
         "https://rekor.sigstore.io/api/v1/log/entries/u1"),
        ({"rekor": {"uuid": "u1", "entry": {}}},
         "https://rekor.sigstore.io/api/v1/log/entries/u1"),
    ])
    def test_anchor_eksikse_ontanimlilar(self, anchor, beklenen):
        pkg = _spdx_eleman(to_spdx(_sertifika(), _defter(), anchor=anchor), "pkg")
        if beklenen is None:
            # DALGA-6-F4 (DUZELTILDI): uuid'siz rekor-anchor bos-uuid'li
            # '.../log/entries/' mis-locatoRU-sentezliyordu; artik ref-EKLENMEZ.
            assert len(pkg["externalRef"]) == 2
            return
        assert len(pkg["externalRef"]) == 3
        assert pkg["externalRef"][2]["locator"] == [beklenen]
        assert "logIndex ?" in pkg["externalRef"][2]["comment"]

    def test_bos_anchor_dict_yanlis_olarak_atlanir(self):
        """`if anchor:` boş dict'i False sayar — 3. ref eklenmez (None ile
        aynı davranış)."""
        pkg = _spdx_eleman(to_spdx(_sertifika(), _defter(), anchor={}), "pkg")
        assert len(pkg["externalRef"]) == 2

    def test_verdict_annotation(self):
        ann = _annotationlar(to_spdx(_sertifika(), _defter()))
        v = next(a for a in ann if a["name"] == "veridict-verdict")
        assert v["annotationType"] == "review"
        assert v["statement"] == "risk_level=low score=0.9 mode=CERTIFICATE"
        base = "https://veridict.dev/spdx/cid-1"
        assert v["subject"] == f"{base}#pkg"

    def test_claim_basina_annotation(self):
        ann = _annotationlar(to_spdx(_sertifika(), _defter()))
        c0 = next(a for a in ann if a["name"] == "veridict-claim0")
        assert c0["statement"] == "claim cl-1: VERIFIED (divergence 0.0)"

    @pytest.mark.parametrize("claims", [[], None])
    def test_claims_yoksa_sadece_verdict(self, claims):
        doc = to_spdx(_sertifika(claims=claims), _defter())
        ann = _annotationlar(doc)
        isimler = {a["name"] for a in ann}
        assert "veridict-verdict" in isimler
        assert not any(n.startswith("veridict-claim") for n in isimler)

    def test_evidence_annotation_producer_dict(self):
        extra = [{"entry_type": "evidence.recorded",
                  "payload": {"evidence_id": "ev-1", "tier": "W2",
                              "stance": "SUPPORTS",
                              "producer": {"identity": "jüri-1"},
                              "evidence_class": "JURY_OPINION"}}]
        ann = _annotationlar(to_spdx(_sertifika(), _defter(extra=extra)))
        ev = next(a for a in ann if a["name"] == "veridict-ev0-0")
        assert ev["statement"] == ("W2 SUPPORTS producer=jüri-1 "
                                   "class=JURY_OPINION")

    def test_evidence_annotation_producer_str(self):
        extra = [{"entry_type": "evidence.recorded",
                  "payload": {"evidence_id": "ev-1", "tier": "W1a",
                              "stance": "REFUTES", "producer": "watcher-x",
                              "evidence_class": "MACHINE_RECEIPT"}}]
        ann = _annotationlar(to_spdx(_sertifika(), _defter(extra=extra)))
        ev = next(a for a in ann if a["name"] == "veridict-ev0-0")
        assert ev["statement"] == ("W1a REFUTES producer=watcher-x "
                                   "class=MACHINE_RECEIPT")

    def test_defterde_olmayan_evidence_atlanir(self):
        """ev-yok defterde yok -> annotation üretilmez (sessiz atlanır)."""
        ann = _annotationlar(to_spdx(_sertifika(), _defter()))
        isimler = {a["name"] for a in ann}
        assert not any(n.startswith("veridict-ev") for n in isimler)

    def test_jury_composition_annotation(self):
        ann = _annotationlar(to_spdx(_sertifika(), _defter()))
        j = next(a for a in ann if a["name"] == "veridict-jury")
        assert j["statement"] == "jury families: fa, fb"

    def test_jury_composition_bos_families_dict_anahtarlari(self):
        """BULGU B2: boş families + dolu dict -> dict ANAHTARLARI listelenir."""
        doc = to_spdx(_sertifika(jury_composition={"families": []}), _defter())
        j = next(a for a in _annotationlar(doc) if a["name"] == "veridict-jury")
        assert j["statement"] == "jury families: families"

    def test_jury_composition_list_ise_attribute_error(self):
        """BULGU B3: liste jury_composition `.get` ile çöker."""
        with pytest.raises(AttributeError):
            to_spdx(_sertifika(jury_composition=["fa", "fb"]), _defter())

    @pytest.mark.parametrize("jc", [None, {}])
    def test_jury_composition_yoksa_annotation_yok(self, jc):
        doc = to_spdx(_sertifika(jury_composition=jc), _defter())
        isimler = {a["name"] for a in _annotationlar(doc)}
        assert "veridict-jury" not in isimler

    def test_dokuman_elementleri(self):
        doc = to_spdx(_sertifika(), _defter())
        base = "https://veridict.dev/spdx/cid-1"
        d = _spdx_eleman(doc, "doc")
        assert d["type"] == "SpdxDocument"
        assert d["name"] == "Veridict audit certificate cid-1"
        assert d["profileConformance"] == ["core", "software",
                                           "simpleLicensing", "ai"]
        assert d["rootElement"] == [f"{base}#pkg"]
        assert d["element"][0] == f"{base}#pkg"

    def test_lisans_iliskileri(self):
        doc = to_spdx(_sertifika(), _defter())
        base = "https://veridict.dev/spdx/cid-1"
        for lic in ("hasDeclaredLicense", "hasConcludedLicense"):
            rel = _spdx_eleman(doc, lic)
            assert rel["type"] == "Relationship"
            assert rel["relationshipType"] == lic
            assert rel["from"] == f"{base}#pkg"
            assert rel["to"] == [f"{base}#license"]

    def test_butun_elemanlar_creation_info_tasiyor(self):
        doc = to_spdx(_sertifika(), _defter())
        for g in doc["@graph"]:
            if g.get("type") == "CreationInfo":
                continue                      # o kendisi creationInfo'dur
            assert g["creationInfo"] == "_:ci"

    def test_cert_ozeti_vsa_ile_ayni(self):
        """İki projeksiyon da aynı kanonik cert özetini gömer."""
        cert = _sertifika()
        vsa = to_vsa(cert, _defter())
        doc = to_spdx(cert, _defter())
        pkg = _spdx_eleman(doc, "pkg")
        ortak = sha256_hex(_canonical(cert))
        assert vsa["predicate"]["inputAttestations"][0]["digest"]["sha256"] == ortak
        assert ortak in pkg["externalRef"][0]["comment"]
