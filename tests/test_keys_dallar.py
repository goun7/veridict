"""Dal-kesen (branch-cutting) testler: veridict/keys.py

Kapsanan public API:
  * SYSTEM_AUTHOR (modül sabiti)
  * KeyStore(ledger)                       — kurulum
  * KeyStore.generate_and_enroll(identity) — ed25519 kayıt + key_id
  * KeyStore.sign(key_id, message)         — imza
  * KeyStore.export_key_file(key_id, path) — özel anahtar dosyaya (0600)
  * KeyStore.load_key_file(path)           — özel anahtar dosyadan
  * KeyStore.public_pem(key_id)            — defterdeki herkese açık yarı
  * KeyStore.verify_signature(pem, msg, sig) — statik doğrulama (herhangi bir
    KeyStore örneği olmadan çağrılabilir)

DAL LİSTESİ:
  generate_and_enroll: 16-hex key_id (sha256(raw-pub)[:16]); deftere
    key.enrolled girdisi {key_id, algorithm=ed25519, purpose,
    identity, public_pem}; iki kayıt farklı key_id; aynı identity iki kez;
    key_id public_pem'den yeniden hesaplanabilir; SYSTEM_AUTHOR yazarı
  sign: base64-ascii; 88 karakter (64 bayt); aynı mesaj=aynı imza
    (deterministik ed25519); farklı mesaj=farklı imza; boş mesaj; unicode
    bayt; bilinmeyen key_id -> KeyError
  export_key_file: JSON {key_id, private_pem}; PKCS8 şifresiz PEM; 0600 izin;
    mevcut dosyayı üstüne yazar (O_TRUNC); yolu olduğu gibi döndürür;
    bilinmeyen key_id -> KeyError
  load_key_file: geri-yükleme aynı key_id; yüklenen anahtar orijinal
    public_pem'e göre doğrulanır; dönüş değeri dosyadaki key_id; yok dosya
    -> FileNotFoundError; bozuk JSON -> ValueError; eksik private_pem ->
    KeyError; çöp PEM -> ValueError
  public_pem: kayıtlı key_id için doğru PEM; bilinmeyen -> KeyError
    ('unknown key_id: ...'); BULGU: load_key_file sonrası defterde kayıt
    yoksa KeyError (public_yarı geri yüklenmez)
  verify_signature: geçerli -> True; değiştirilmiş mesaj -> False;
    değiştirilmiş imza -> False; başka anahtarın imzası -> False;
    çöp base64 -> False; boş imza -> False; dolamasız base64 -> False;
    çöp PEM -> False; EC PEM (farklı algoritma) -> False (TypeError yolu);
    None/sig/str mesaj -> False (TypeError yolu); statik çağrı örneksiz

BULGULAR (production koduna DOKUNULMADI — burada belgelendi):
  B1: load_key_file deftere ENROLL ETMEZ — özel anahtar gelir ama
      public_pem(key_id) o anahtar için KeyError verir (kayıt girdisi
      yok). Amaçlı tasarım olabilir (CLI sahibi dosyayı taşır); belgelidir.
  B2: generate_and_enroll identity değerini DOĞRULAMAZ — boş string ve
      unicode identity kabul edilir (sadece payload'a yazılır).
  B3: export_key_file Özel anahtarı ŞİFRESİZ PKCS8 olarak yazar — dosyayı
      okuyan herkes imzalayabilir (0600 dosya izni tek korumadır).
"""
from __future__ import annotations

import base64
import json
import os
import stat

import pytest
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from veridict.keys import SYSTEM_AUTHOR, KeyStore
from veridict.ledger import Ledger
from veridict.utils import sha256_hex


def _mağaza() -> tuple[Ledger, KeyStore]:
    led = Ledger()
    return led, KeyStore(led)


# ---------------------------------------------------------------------------
# SYSTEM_AUTHOR + kurulum
# ---------------------------------------------------------------------------

class TestSistemYazarı:
    """SYSTEM_AUTHOR sabiti ve KeyStore kurulum dalları."""

    def test_sistem_yazarı_değeri(self):
        assert SYSTEM_AUTHOR.kind == "system"
        assert SYSTEM_AUTHOR.identity == "veridict-core"
        assert SYSTEM_AUTHOR.version == "0.1.0"

    def test_boş_anahtar_deposu(self):
        _, ks = _mağaza()
        assert ks.ledger is not None
        assert list(ks._keys) == []
        assert len(ks.ledger.entries) == 0


# ---------------------------------------------------------------------------
# generate_and_enroll
# ---------------------------------------------------------------------------

class TestGenerateAndEnroll:
    """generate_and_enroll dalları: key_id biçimi, defter girdisi, rastgelelik,
    identity taşıma, key_id'nin public_pem'den yeniden hesaplanabilirliği."""

    def test_key_id_16_hex(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        assert isinstance(kid, str)
        assert len(kid) == 16
        int(kid, 16)                      # geçerli onaltılık

    def test_key_id_public_pemden_yeniden(self):
        led, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        pub_pem = ks.public_pem(kid)
        raw = load_pem_public_key(pub_pem.encode()).public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        assert kid == sha256_hex(raw)[:16]

    def test_defter_girdisi_tam(self):
        led, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        girdiler = led.query("key.enrolled")
        assert len(girdiler) == 1
        e = girdiler[0]
        assert e["entry_type"] == "key.enrolled"
        assert e["seq"] == 0
        assert e["payload"]["key_id"] == kid
        assert e["payload"]["algorithm"] == "ed25519"
        assert e["payload"]["purpose"] == "certificate-signing"
        assert e["payload"]["identity"] == "dal-test"
        assert "BEGIN PUBLIC KEY" in e["payload"]["public_pem"]

    def test_yazar_sistem(self):
        led, ks = _mağaza()
        ks.generate_and_enroll("dal-test")
        e = led.query("key.enrolled")[0]
        assert e["author"] == SYSTEM_AUTHOR.to_dict()

    def test_iki_kayıt_farklı_key_id(self):
        led, ks = _mağaza()
        a = ks.generate_and_enroll("dal-a")
        b = ks.generate_and_enroll("dal-b")
        assert a != b
        assert len(ks._keys) == 2
        assert len(led.query("key.enrolled")) == 2
        assert [e["seq"] for e in led.query("key.enrolled")] == [0, 1]

    def test_aynı_identity_iki_kez_farklı_anahtar(self):
        led, ks = _mağaza()
        a = ks.generate_and_enroll("aynı")
        b = ks.generate_and_enroll("aynı")
        assert a != b
        for e in led.query("key.enrolled"):
            assert e["payload"]["identity"] == "aynı"

    def test_kayıttan_sonra_özel_anahtar_imzalayabilir(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, b"mesaj")
        assert KeyStore.verify_signature(ks.public_pem(kid), b"mesaj", sig)

    def test_public_pem_farklı_anahtarlarda_farklı(self):
        _, ks = _mağaza()
        a = ks.generate_and_enroll("dal-a")
        b = ks.generate_and_enroll("dal-b")
        assert ks.public_pem(a) != ks.public_pem(b)

    @pytest.mark.parametrize("identity", ["", "İstanbul", "a" * 200, "x y z"])
    def test_identity_doğrulanmaz(self, identity):
        """B2: identity değeri sadece payload'a yazılır, doğrulanmaz."""
        led, ks = _mağaza()
        kid = ks.generate_and_enroll(identity)
        assert led.query("key.enrolled")[0]["payload"]["identity"] == identity


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------

class TestSign:
    """sign dalları: base64 biçim, determinizm, mesaj çeşitleri,
    bilinmeyen key_id."""

    def test_base64_ascii_88_karakter(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, b"mesaj")
        assert isinstance(sig, str)
        assert sig.isascii()
        assert len(sig) == 88                  # 64 bayt -> base64
        assert len(base64.b64decode(sig)) == 64

    def test_aynı_mesaj_aynı_imza(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        assert ks.sign(kid, b"mesaj") == ks.sign(kid, b"mesaj")

    def test_farklı_mesaj_farklı_imza(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        assert ks.sign(kid, b"bir") != ks.sign(kid, b"iki")

    @pytest.mark.parametrize("mesaj", [b"", b"a", b"\x00\xff"*50,
                                       "İstanbul".encode("utf-8")])
    def test_mesaj_çeşitleri_doğrulanır(self, mesaj):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, mesaj)
        assert KeyStore.verify_signature(ks.public_pem(kid), mesaj, sig)

    def test_bilinmeyen_key_id(self):
        _, ks = _mağaza()
        ks.generate_and_enroll("dal-test")
        with pytest.raises(KeyError):
            ks.sign("olmayan-key", b"mesaj")


# ---------------------------------------------------------------------------
# export_key_file / load_key_file
# ---------------------------------------------------------------------------

class TestAnahtarDosyası:
    """export/load dalları: geri-yükleme, dosya biçimi, 0600 izin,
    üstüne yazma, hata yolları."""

    def test_geri_yükleme_aynı_key_id(self, tmp_path):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        yol = str(tmp_path / "anahtar.json")
        assert ks.export_key_file(kid, yol) == yol
        assert ks.load_key_file(yol) == kid

    def test_yüklenen_anahtar_orijinal_pem_doğrular(self, tmp_path):
        """Özel yarı süreç sınırını aştıktan sonra hâlâ imzalayabilir."""
        led, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        pem = ks.public_pem(kid)
        yol = str(tmp_path / "anahtar.json")
        ks.export_key_file(kid, yol)

        _, ks2 = _mağaza()                    # TAMAMEN YENİ depo + defter
        assert kid not in ks2._keys
        assert ks2.load_key_file(yol) == kid
        sig = ks2.sign(kid, "süreç-ötesi".encode("utf-8"))
        assert KeyStore.verify_signature(pem, "süreç-ötesi".encode("utf-8"), sig)

    def test_dosya_içeriği_pkc8(self, tmp_path):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        yol = str(tmp_path / "anahtar.json")
        ks.export_key_file(kid, yol)
        with open(yol, encoding="utf-8") as f:
            veri = json.load(f)
        assert set(veri) == {"key_id", "private_pem"}
        assert veri["key_id"] == kid
        assert "BEGIN PRIVATE KEY" in veri["private_pem"]
        assert "ENCRYPTED" not in veri["private_pem"]   # B3: şifresiz

    def test_dosya_0600_izin(self, tmp_path):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        yol = str(tmp_path / "anahtar.json")
        ks.export_key_file(kid, yol)
        kip = stat.S_IMODE(os.stat(yol).st_mode)
        assert kip == 0o600

    def test_mevcut_dosyanın_üstüne_yazar(self, tmp_path):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        yol = str(tmp_path / "anahtar.json")
        with open(yol, "w", encoding="utf-8") as f:
            f.write("eski çöp içerik")
        ks.export_key_file(kid, yol)
        with open(yol, encoding="utf-8") as f:
            assert json.load(f)["key_id"] == kid

    def test_export_bilinmeyen_key_id(self, tmp_path):
        _, ks = _mağaza()
        ks.generate_and_enroll("dal-test")
        with pytest.raises(KeyError):
            ks.export_key_file("olmayan", str(tmp_path / "x.json"))

    def test_yok_dosya(self, tmp_path):
        _, ks = _mağaza()
        with pytest.raises(FileNotFoundError):
            ks.load_key_file(str(tmp_path / "yok.json"))

    def test_bozuk_json(self, tmp_path):
        yol = str(tmp_path / "bozuk.json")
        with open(yol, "w", encoding="utf-8") as f:
            f.write("{bu json değil")
        _, ks = _mağaza()
        with pytest.raises(ValueError):          # JSONDecodeError < ValueError
            ks.load_key_file(yol)

    def test_eksik_private_pem(self, tmp_path):
        yol = str(tmp_path / "eksik.json")
        with open(yol, "w", encoding="utf-8") as f:
            json.dump({"key_id": "abc"}, f)
        _, ks = _mağaza()
        with pytest.raises(KeyError):
            ks.load_key_file(yol)

    def test_çöp_pem(self, tmp_path):
        yol = str(tmp_path / "çöp.json")
        with open(yol, "w", encoding="utf-8") as f:
            json.dump({"key_id": "abc", "private_pem": "çöp PEM"}, f)
        _, ks = _mağaza()
        with pytest.raises(ValueError):
            ks.load_key_file(yol)

    def test_geri_yüklenen_anhtarın_pem_i_defterde_yok(self, tmp_path):
        """B1: load_key_file enroll ETMEZ — public_pem KeyError verir."""
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        yol = str(tmp_path / "anahtar.json")
        ks.export_key_file(kid, yol)

        _, ks2 = _mağaza()
        ks2.load_key_file(yol)
        assert kid in ks2._keys
        with pytest.raises(KeyError, match="unknown key_id"):
            ks2.public_pem(kid)

    def test_iki_kez_yükleme_idempotent(self, tmp_path):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        yol = str(tmp_path / "anahtar.json")
        ks.export_key_file(kid, yol)
        assert ks.load_key_file(yol) == kid
        assert ks.load_key_file(yol) == kid
        assert len(ks._keys) == 1


# ---------------------------------------------------------------------------
# public_pem
# ---------------------------------------------------------------------------

class TestPublicPem:
    """public_pem dalları: doğru PEM, bilinmeyen key_id, çoklu anahtar."""

    def test_doğru_pem(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        pem = ks.public_pem(kid)
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert pem.rstrip().endswith("-----END PUBLIC KEY-----")
        load_pem_public_key(pem.encode())       # geçerli PEM

    def test_bilinmeyen_key_id_mesaj(self):
        _, ks = _mağaza()
        ks.generate_and_enroll("dal-test")
        with pytest.raises(KeyError, match="unknown key_id: deadbeef"):
            ks.public_pem("deadbeef")

    def test_çoklu_anahtar_doğru_peşleşme(self):
        _, ks = _mağaza()
        a = ks.generate_and_enroll("dal-a")
        b = ks.generate_and_enroll("dal-b")
        assert ks.public_pem(a) != ks.public_pem(b)
        # imza + doğru pem eşleşmesi
        assert KeyStore.verify_signature(ks.public_pem(a), b"m", ks.sign(a, b"m"))
        assert not KeyStore.verify_signature(ks.public_pem(b), b"m", ks.sign(a, b"m"))

    def test_defter_girdisi_silindiyse_keyerror(self):
        """Defter elle boşaltılırsa public_pem bulamaz."""
        led, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        del led.entries[:]                       # işletme girdisi kaldırıldı
        with pytest.raises(KeyError):
            ks.public_pem(kid)


# ---------------------------------------------------------------------------
# verify_signature (statik yöntem)
# ---------------------------------------------------------------------------

class TestVerifySignature:
    """verify_signature dalları: başarı, değiştirilme, algoritma uyumsuzluğu,
    biçim hataları, tip hataları, örneksiz (static) çağrı."""

    def test_geçerli(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, b"mesaj")
        assert KeyStore.verify_signature(ks.public_pem(kid), b"mesaj", sig) is True

    def test_statik_örneksiz(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        pem = ks.public_pem(kid)
        sig = ks.sign(kid, b"mesaj")
        assert KeyStore.verify_signature(pem, b"mesaj", sig)

    def test_değiştirilmiş_mesaj(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, b"orijinal")
        assert KeyStore.verify_signature(ks.public_pem(kid), "değişti".encode("utf-8"), sig) is False

    def test_değiştirilmiş_imza(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, b"orijinal")
        bozuk = ("A" if sig[0] != "A" else "B") + sig[1:]
        assert KeyStore.verify_signature(ks.public_pem(kid), b"orijinal", bozuk) is False

    def test_başka_anahtarın_imzası(self):
        _, ks = _mağaza()
        a = ks.generate_and_enroll("dal-a")
        b = ks.generate_and_enroll("dal-b")
        sig = ks.sign(a, b"mesaj")
        assert KeyStore.verify_signature(ks.public_pem(b), b"mesaj", sig) is False

    def test_çöp_base64_imza(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        assert KeyStore.verify_signature(ks.public_pem(kid), b"m",
                                         "!!!base64-değil!!!") is False

    def test_boş_imza(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        assert KeyStore.verify_signature(ks.public_pem(kid), b"m", "") is False

    def test_dolamasız_base64(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, b"m")
        assert KeyStore.verify_signature(ks.public_pem(kid), b"m",
                                         sig[:-2]) is False    # padding eksik

    def test_kısa_imza(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        kısa = base64.b64encode(b"on" * 5).decode()
        assert KeyStore.verify_signature(ks.public_pem(kid), b"m", kısa) is False

    def test_unicode_imza(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        assert KeyStore.verify_signature(ks.public_pem(kid), b"m",
                                         "İmzaçöp") is False

    def test_çöp_pem(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, b"m")
        assert KeyStore.verify_signature("bir pem değil", b"m", sig) is False

    def test_boş_pem(self):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, b"m")
        assert KeyStore.verify_signature("", b"m", sig) is False

    def test_farklı_algoritma_pem(self):
        """EC P-256 PEM ile ed25519 imzası -> TypeError yolu -> False."""
        from cryptography.hazmat.primitives.asymmetric import ec
        ec_priv = ec.generate_private_key(ec.SECP256R1())
        ec_pem = ec_priv.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, b"m")
        assert KeyStore.verify_signature(ec_pem, b"m", sig) is False

    @pytest.mark.parametrize("mesaj", [None, "metin", 42, b""])
    def test_mesaj_tip_hataları(self, mesaj):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        sig = ks.sign(kid, b"m")
        assert KeyStore.verify_signature(ks.public_pem(kid), mesaj, sig) is False

    @pytest.mark.parametrize("sig", [None, 42, b"AAAA"])
    def test_imza_tip_hataları(self, sig):
        _, ks = _mağaza()
        kid = ks.generate_and_enroll("dal-test")
        assert KeyStore.verify_signature(ks.public_pem(kid), b"m", sig) is False
