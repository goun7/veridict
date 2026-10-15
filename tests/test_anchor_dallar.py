"""Dal-kesen (branch-cutting) testler: veridict/anchor.py

Kapsanan public API:
  * REKOR_SERVER / ANCHOR_TYPE / REKOR_PUBLIC_KEY_PEM / REFRESH_RECIPE
  * bound_fields(cert)        — bağlanmış alan çıkarımı
  * anchor_digest(bound)      — sha256(sorted-key canonical JSON)
  * leaf_hash(body)           — RFC 6962 Merkle yaprağı
  * locate_checkpoint(...)    — checkpoint.anchored girdisini bulma + redler
  * publish(...)              — Rekor'a gönderim (httpx monkeypatch ile stub)
  * verify(sidecar, cert?)    — çevrimdışı kripto doğrulama (asla raise etmez)

AĞ YOK: publish, httpx.post monkeypatch ile sahte (in-memory) bir Rekor'a
gider; her şey saf bellek içidir.

DAL LİSTESİ:
  bound_fields: tam sertifika; ledger_anchor yok/None -> seq None, chain "";
    signatures yok/boş -> key_id ""; sigs[0] key_id'siz -> ""; cert_id yok
  anchor_digest: 64-hex; deterministik; anahtar sırası BAĞIMSIZ; farklı
    cert_id -> farklı digest
  leaf_hash: 32 bayt; sha256(0x00 || body); boş body; deterministik
  locate_checkpoint: bulma; yanlış seq -> RuntimeError; yanlış entry_type ->
    RuntimeError; chain_hash uyuşmazlığı -> RuntimeError; boş liste; seq
    None; tip-katısı (str vs int); ilk eşleşme kazanır
  publish: başarı (sidecar şekli + uuid=treeID||leaf||treeID); istek gövdesi
    hashedrekord + prehash imzası publicKey'den doğrulanır; varsayılan ve
    iz-düşmeli rekor_url; timeout aktarımı; HTTP 400/500 -> RuntimeError;
    HTTP 200 -> başarı; boş giriş haritası -> ValueError (B4); iki giriş ->
    ValueError; checkpoint yok -> RuntimeError
  verify: tam başarı + summary; cert=None crypto-only; cert uyuşmazlığı;
    digest yeniden-hesap uyuşmazlığı; body decode edilemez; yanlış kind;
    note bozuk (\\n\\n yok); note 2/4 satır; rootHash uyuşmazlığı; note root
    base64 değil -> ATLANIR (B1); tree_size <= logIndex; tree_size rakam
    değil -> ATLANIR; uuid 96 değil -> ATLANIR; uuid içinde leaf yok; SET
    yok/bozuk/yabancı anahtar -> red; checkpoint note imzası bozuk -> red;
    gerçek sabit anahtar yabancı logu reddeder (fail-closed); boş sidecar

BULGULAR (production koduna DOKUNULMADI — burada belgelendi):
  B1: verify'in rootHash çapraz-kontrolü, note'un root satırı base64
      DEĞİLSE sessizce ATLANIR (root_from_note="" → uyarı eklenmez) —
      deforme olmuş bir note fail-open davranır.
  B2: tree_size rakam değilse (örn. "on") logIndex-kapsam kontrolü de
      atlanır; summary.tree_size_at_anchor ham dize olarak kalır.
  B3: uuid tam 96 karakter DEĞİLSE leaf-gömme kontrolü atlanır.
  B4: publish boş (200) giriş haritası aldığında RuntimeError DEĞİL
      ValueError verir — docstring "Raises RuntimeError on any rejection"
      sözüyle çelişir.
  B5: verify(None) AttributeError verir — docstring "never raises on bad
      data" yalnız dict biçimli girdiler için geçerlidir.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from veridict import anchor


# ---------------------------------------------------------------------------
# sabitler
# ---------------------------------------------------------------------------

class TestSabitler:
    """Modül sabitleri: sunucu, tür, sabitlenmiş gerçek Rekor anahtarı,
    TUF yenileme tarifi."""

    def test_rekor_sunucusu(self):
        assert anchor.REKOR_SERVER == "https://rekor.sigstore.dev"

    def test_anchor_türü(self):
        assert anchor.ANCHOR_TYPE == "veridict-anchor-1"

    def test_sabitlenmiş_anahtar_p256(self):
        pub = load_pem_public_key(anchor.REKOR_PUBLIC_KEY_PEM.encode())
        assert isinstance(pub.curve, ec.SECP256R1)
        assert anchor.REKOR_PUBLIC_KEY_PEM.startswith("-----BEGIN PUBLIC KEY-----")

    def test_yenileme_tarifi(self):
        assert "5.targets.json" in anchor.REFRESH_RECIPE
        assert "rekor.pub" in anchor.REFRESH_RECIPE
        assert "REKOR_PUBLIC_KEY_PEM" in anchor.REFRESH_RECIPE


# ---------------------------------------------------------------------------
# bound_fields / anchor_digest / leaf_hash
# ---------------------------------------------------------------------------

class TestBoundFields:
    """bound_fields dalları: tam sertifika; eksik ledger_anchor; eksik
    signatures; sigs[0] key_id'siz; eksik cert_id."""

    def test_tam_sertifika(self):
        cert = {"cert_id": "a" * 24, "signatures": [{"key_id": "k1"}],
                "ledger_anchor": {"checkpoint_seq": 7, "chain_hash": "c" * 64}}
        assert anchor.bound_fields(cert) == {
            "anchor": anchor.ANCHOR_TYPE, "cert_id": "a" * 24,
            "key_id": "k1", "checkpoint_seq": 7, "chain_hash": "c" * 64}

    def test_anchor_türü_her_zaman(self):
        assert anchor.bound_fields({})["anchor"] == anchor.ANCHOR_TYPE

    @pytest.mark.parametrize("cert", [
        {},
        {"ledger_anchor": None},
        {"ledger_anchor": {}},
    ])
    def test_ledger_anchor_yok(self, cert):
        b = anchor.bound_fields(cert)
        assert b["checkpoint_seq"] is None
        assert b["chain_hash"] == ""

    @pytest.mark.parametrize("sigs", [None, [], [{"dig": 1}]])
    def test_signatures_yok_key_id_boş(self, sigs):
        cert = {"cert_id": "x", "signatures": sigs,
                "ledger_anchor": {"checkpoint_seq": 1, "chain_hash": "c"}}
        assert anchor.bound_fields(cert)["key_id"] == ""

    def test_cert_id_yok(self):
        assert anchor.bound_fields({})["cert_id"] == ""


class TestAnchorDigest:
    """anchor_digest dalları: 64-hex, deterministik, anahtar sırası
    bağımsız (sorted-key canonical), farklı bağ farklı digest."""

    def test_64_hex(self):
        d = anchor.anchor_digest({"cert_id": "a", "chain_hash": "b"})
        assert len(d) == 64
        int(d, 16)

    def test_deterministik(self):
        b = {"cert_id": "a", "chain_hash": "b"}
        assert anchor.anchor_digest(b) == anchor.anchor_digest(copy.deepcopy(b))

    def test_anahtar_sırası_bağımsız(self):
        assert anchor.anchor_digest({"a": 1, "b": 2, "c": 3}) == \
            anchor.anchor_digest({"c": 3, "b": 2, "a": 1})

    def test_farklı_bağ_farklı_digest(self):
        a = anchor.bound_fields({"cert_id": "a" * 24})
        b = anchor.bound_fields({"cert_id": "b" * 24})
        assert anchor.anchor_digest(a) != anchor.anchor_digest(b)

    def test_boş_dict(self):
        assert anchor.anchor_digest({}) == hashlib.sha256(b"{}").hexdigest()

    def test_canonical_sıkıştırılmış(self):
        from veridict.anchor import _canonical
        assert _canonical({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


class TestLeafHash:
    """leaf_hash dalları: RFC 6962 sha256(0x00 || data); 32 bayt;
    deterministik; boş body."""

    def test_yapı_ve_değer(self):
        body = b"abc"
        assert anchor.leaf_hash(body) == hashlib.sha256(b"\x00" + body).digest()

    def test_boş_body(self):
        assert anchor.leaf_hash(b"") == hashlib.sha256(b"\x00").digest()

    def test_32_bayt_deterministik(self):
        h = anchor.leaf_hash(b"x")
        assert len(h) == 32
        assert h == anchor.leaf_hash(b"x")
        assert h != anchor.leaf_hash(b"y")


# ---------------------------------------------------------------------------
# locate_checkpoint
# ---------------------------------------------------------------------------

def _defter(seq=7, chain="c" * 64, entry_type="checkpoint.anchored"):
    return [{"seq": seq, "entry_type": entry_type, "payload": {"chain_hash": chain}}]


def _bağ(seq=7, chain="c" * 64):
    return {"anchor": anchor.ANCHOR_TYPE, "cert_id": "a" * 24, "key_id": "k1",
            "checkpoint_seq": seq, "chain_hash": chain}


class TestLocateCheckpoint:
    """locate_checkpoint dalları: bulma; seq yok; yanlış tür; chain uyuşmazlığı;
    boş liste; seq None; tip-katısı; ilk eşleşme."""

    def test_bulma(self):
        defter = _defter()
        assert anchor.locate_checkpoint(defter, _bağ()) is defter[0]

    def test_seq_yok(self):
        with pytest.raises(RuntimeError, match="no checkpoint.anchored entry at seq 9"):
            anchor.locate_checkpoint(_defter(), _bağ(seq=9))

    def test_yanlış_entry_type(self):
        with pytest.raises(RuntimeError, match="no checkpoint.anchored"):
            anchor.locate_checkpoint(_defter(entry_type="checkpoint.pending"),
                                     _bağ())

    def test_chain_uyuşmazlığı(self):
        with pytest.raises(RuntimeError, match="chain_hash at checkpoint_seq disagrees"):
            anchor.locate_checkpoint(_defter(chain="d" * 64), _bağ())

    def test_boş_liste(self):
        with pytest.raises(RuntimeError, match="refusing to anchor"):
            anchor.locate_checkpoint([], _bağ())

    def test_seq_none(self):
        with pytest.raises(RuntimeError):
            anchor.locate_checkpoint(_defter(), _bağ(seq=None))

    def test_seq_tip_katısı(self):
        """"7" != 7 — eşleşme katıdır (değilse RuntimeError)."""
        with pytest.raises(RuntimeError):
            anchor.locate_checkpoint([{"seq": "7",
                                       "entry_type": "checkpoint.anchored",
                                       "payload": {"chain_hash": "c" * 64}}],
                                     _bağ())

    def test_ilk_eşleşme_kazanır(self):
        g1 = {"seq": 3, "entry_type": "checkpoint.anchored",
              "payload": {"chain_hash": "e" * 64}}
        g2 = {"seq": 3, "entry_type": "checkpoint.anchored",
              "payload": {"chain_hash": "e" * 64}}
        assert anchor.locate_checkpoint([g1, g2], _bağ(seq=3, chain="e" * 64)) is g1


# ---------------------------------------------------------------------------
# sahte Rekor + enstrümanlar
# ---------------------------------------------------------------------------

class _Yanıt:
    def __init__(self, payload, status=201, text=None):
        self._p = payload
        self.status_code = status
        self.text = text if text is not None else json.dumps(payload)

    def json(self):
        return self._p


class _SahteRekor:
    """Bellek içi Rekor: uuid=treeID||leaf||treeID hesaplar, canonical SET ve
    checkpoint note'unu biletli bir ECDSA P-256 anahtarıyla imzalar. Ağ YOK."""

    def __init__(self):
        self.log_key = ec.generate_private_key(ec.SECP256R1())
        self.pin = self.log_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        self.tree_id = "aabbccddeeff0011"
        self.index = 100
        self.gelen = []
        self.tree_size = "10"
        self.proof_index = 3

    def __call__(self, url, json=None, timeout=None, **kw):
        self.gelen.append((url, json, timeout))
        body = anchor._canonical(json)
        leaf = hashlib.sha256(b"\x00" + body).hexdigest()
        uuid = f"{self.tree_id}{leaf}{self.tree_id}"
        entry = {"body": base64.b64encode(body).decode(),
                 "integratedTime": 1790000000,
                 "logID": "c0d2" * 16,
                 "logIndex": self.index}
        set_sig = self.log_key.sign(
            hashlib.sha256(anchor._canonical(entry)).digest(),
            ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        head = ("sahte.rekor - 0\n" + self.tree_size + "\n"
                + base64.b64encode(b"\x11" * 32).decode())
        note_sig = self.log_key.sign(
            hashlib.sha256((head + "\n").encode()).digest(),
            ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        entry["verification"] = {
            "signedEntryTimestamp": base64.b64encode(set_sig).decode(),
            "inclusionProof": {
                "checkpoint": head + "\n\n— sahte "
                + base64.b64encode(b"\xc0\xd2\x3d\x6a" + note_sig).decode() + "\n",
                "hashes": [], "logIndex": self.proof_index,
                "rootHash": (b"\x11" * 32).hex(),
                "treeSize": int(self.tree_size)}}
        self.index += 1
        return _Yanıt({uuid: entry})


@pytest.fixture
def rekor(monkeypatch):
    sahte = _SahteRekor()
    monkeypatch.setattr("httpx.post", sahte)
    return sahte


def _sertifika(seq=7, chain="c" * 64, cert_id="a" * 24, key_id="k1"):
    return {"cert_id": cert_id,
            "signatures": [{"key_id": key_id}],
            "ledger_anchor": {"checkpoint_seq": seq, "chain_hash": chain}}


class TestPublish:
    """publish dalları: başarı, istek gövdesi biçimi, url/timeout, HTTP
    retleri, bozuk yanıtlar, checkpoint yok."""

    def test_başarı_sidecar_şekli(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        bound = anchor.bound_fields(_sertifika())
        assert sc["anchor_version"] == anchor.ANCHOR_TYPE
        assert sc["bound"] == bound
        assert sc["digest"] == anchor.anchor_digest(bound)
        assert sc["rekor"]["server"] == anchor.REKOR_SERVER
        assert set(sc["rekor"]) == {"server", "uuid", "entry"}
        assert len(sc["rekor"]["uuid"]) == 96

    def test_uuid_yaprak_gömer(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        body = base64.b64decode(sc["rekor"]["entry"]["body"])
        uuid = sc["rekor"]["uuid"]
        assert uuid[16:80] == anchor.leaf_hash(body).hex()

    def test_istek_gövdesi_hashedrekord(self, rekor):
        anchor.publish(_defter(), _sertifika())
        url, body, timeout = rekor.gelen[-1]
        assert url == anchor.REKOR_SERVER + "/api/v1/log/entries"
        assert body["apiVersion"] == "0.0.1"
        assert body["kind"] == "hashedrekord"
        assert body["spec"]["data"]["hash"]["algorithm"] == "sha256"

    def test_istek_imzası_public_keyden_doğrulanır(self, rekor):
        """Gönderilen imza, gövdedeki publicKey ile prehashed digest üzerinden
        doğrulanabilir olmalı."""
        anchor.publish(_defter(), _sertifika())
        url, body, timeout = rekor.gelen[-1]
        digest = body["spec"]["data"]["hash"]["value"]
        der = base64.b64decode(body["spec"]["signature"]["content"])
        pem = base64.b64decode(
            body["spec"]["signature"]["publicKey"]["content"]).decode()
        pub = load_pem_public_key(pem.encode())
        # Prehashed: imza bytes.fromhex(digest) özetinin KENDİSİ üzerinedir
        pub.verify(der, bytes.fromhex(digest),
                   ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))

    def test_digest_bağdan_geliyor(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        url, body, timeout = rekor.gelen[-1]
        assert body["spec"]["data"]["hash"]["value"] == sc["digest"]

    def test_iz_düşmeli_url(self, rekor):
        anchor.publish(_defter(), _sertifika(),
                       rekor_url="https://rekor.example.com/")
        assert rekor.gelen[-1][0] == "https://rekor.example.com/api/v1/log/entries"

    def test_timeout_aktarımı(self, rekor):
        anchor.publish(_defter(), _sertifika(), timeout=1.5)
        assert rekor.gelen[-1][2] == 1.5

    def test_timeout_varsayılan(self, rekor):
        anchor.publish(_defter(), _sertifika())
        assert rekor.gelen[-1][2] == 60.0

    def test_http_400_reddi(self, rekor, monkeypatch):
        monkeypatch.setattr(
            "httpx.post", lambda *a, **kw: _Yanıt({}, status=400, text="kötü istek"))
        with pytest.raises(RuntimeError, match="rekor rejected the anchor \\(HTTP 400\\)"):
            anchor.publish(_defter(), _sertifika())

    def test_http_500_reddi(self, rekor, monkeypatch):
        monkeypatch.setattr(
            "httpx.post", lambda *a, **kw: _Yanıt({}, status=500, text="iç hata"))
        with pytest.raises(RuntimeError, match="HTTP 500"):
            anchor.publish(_defter(), _sertifika())

    def test_http_200_başarı(self, rekor, monkeypatch):
        sc = anchor.publish(_defter(), _sertifika())   # 201
        # 200 da kabul edilir: SADECE giriş haritası (uuid -> entry) ile
        cevap = _Yanıt({sc["rekor"]["uuid"]: sc["rekor"]["entry"]}, status=200)
        monkeypatch.setattr("httpx.post", lambda *a, **kw: cevap)
        sc2 = anchor.publish(_defter(), _sertifika())
        assert sc2["rekor"]["uuid"] == sc["rekor"]["uuid"]

    def test_boş_giri_haritası_valueerror(self, rekor, monkeypatch):
        """B4: boş 200 yanıtı RuntimeError değil ValueError verir."""
        monkeypatch.setattr("httpx.post", lambda *a, **kw: _Yanıt({}, status=201))
        with pytest.raises(ValueError):
            anchor.publish(_defter(), _sertifika())

    def test_iki_giri_valueerror(self, rekor, monkeypatch):
        e = anchor.publish(_defter(), _sertifika())["rekor"]["entry"]
        monkeypatch.setattr(
            "httpx.post", lambda *a, **kw: _Yanıt({"u1": e, "u2": e}, status=201))
        with pytest.raises(ValueError, match="too many values"):
            anchor.publish(_defter(), _sertifika())

    def test_checkpoint_yok_reddi(self, rekor):
        with pytest.raises(RuntimeError, match="no checkpoint.anchored entry"):
            anchor.publish(_defter(seq=99), _sertifika())

    def test_chain_uyuşmazlığı_reddi(self, rekor):
        with pytest.raises(RuntimeError, match="disagrees"):
            anchor.publish(_defter(chain="d" * 64), _sertifika())


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

class TestVerify:
    """verify dalları: tam başarı, crypto-only, uyuşmazlıklar, deforme
    girdiler, fail-closed sabit anahtar."""

    @staticmethod
    def _note_uygula(rekor, notlar, head):
        """Note imzası head+'\\n' üzerinedir — head'i değiştirince yeniden
        imzalamak gerekir, yoksa note-sig kontrolü her dalı geçersiz kılar."""
        note_sig = rekor.log_key.sign(
            hashlib.sha256((head + "\n").encode()).digest(),
            ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        notlar["checkpoint"] = head + "\n\n— sahte " + base64.b64encode(
            b"\xc0\xd2\x3d\x6a" + note_sig).decode() + "\n"

    @staticmethod
    def _head(notlar):
        return notlar["checkpoint"].partition("\n\n")[0]

    def test_tam_başarı(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is True, res["errors"]
        assert res["errors"] == []
        assert res["summary"]["cert_id"] == "a" * 24
        assert res["summary"]["checkpoint_seq"] == 7
        assert res["summary"]["chain_hash"] == "c" * 64
        assert res["summary"]["digest"] == sc["digest"]
        assert res["summary"]["logIndex"] == 100
        assert res["summary"]["integratedTime"] == 1790000000
        assert res["summary"]["server"] == anchor.REKOR_SERVER
        assert res["summary"]["uuid"] == sc["rekor"]["uuid"]
        assert res["summary"]["tree_size_at_anchor"] == "10"

    def test_crypto_only_cert_yok(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        res = anchor.verify(sc, None, rekor_key_pem=rekor.pin)
        assert res["valid"] is True, res["errors"]
        assert res["summary"]["cert_id"] == sc["bound"]["cert_id"]

    def test_cert_uyuşmazlığı(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        başka = _sertifika(cert_id="b" * 24)
        res = anchor.verify(sc, başka, rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("does not match the certificate" in e for e in res["errors"])

    def test_crypto_only_sidecar_cert_verilince(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        sc["bound"] = {"anchor": anchor.ANCHOR_TYPE, "cert_id": "", "key_id": "",
                       "checkpoint_seq": None, "chain_hash": ""}
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("does not match the certificate" in e for e in res["errors"])

    def test_digest_yeniden_hesap_uyuşmazlığı(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        sc["digest"] = "f" * 64
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        hatalar = " | ".join(res["errors"])
        assert "anchor digest does not recompute from the binding" in hatalar
        assert "entry hash does not match the anchor digest" in hatalar

    def test_body_hash_değiştirilmiş(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        body = json.loads(base64.b64decode(sc["rekor"]["entry"]["body"]))
        body["spec"]["data"]["hash"]["value"] = "e" * 64
        sc["rekor"]["entry"]["body"] = base64.b64encode(
            json.dumps(body).encode()).decode()
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        hatalar = " | ".join(res["errors"])
        assert "entry hash does not match the anchor digest" in hatalar
        assert "SET signature" in hatalar

    @pytest.mark.parametrize("body", ["çöp değil base64", "ew==", ""])
    def test_body_decode_edilemez(self, rekor, body):
        """ew== = b'{' — geçerli base64 ama geçersiz JSON."""
        sc = anchor.publish(_defter(), _sertifika())
        sc["rekor"]["entry"]["body"] = body
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("entry body undecodable" in e for e in res["errors"])

    def test_yanlış_kind(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        body = json.loads(base64.b64decode(sc["rekor"]["entry"]["body"]))
        body["kind"] = "intoto"
        sc["rekor"]["entry"]["body"] = base64.b64encode(
            json.dumps(body).encode()).decode()
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("unexpected entry kind" in e for e in res["errors"])

    def test_note_bozuk_ayraç(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        sc["rekor"]["entry"]["verification"]["inclusionProof"]["checkpoint"] = \
            "başlık satırı"
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("checkpoint note malformed" in e for e in res["errors"])
        # erken dönüş: başka kripto hataları eklenmez
        assert not any("SET signature" in e for e in res["errors"])

    @pytest.mark.parametrize("satır_sayısı,ek", [(2, ""), (4, "\n dördüncü")])
    def test_note_satır_sayısı(self, rekor, satır_sayısı, ek):
        sc = anchor.publish(_defter(), _sertifika())
        notlar = sc["rekor"]["entry"]["verification"]["inclusionProof"]
        baş = notlar["checkpoint"].partition("\n\n")[0]
        satırlar = baş.split("\n")
        if satır_sayısı == 2:
            notlar["checkpoint"] = "\n".join(satırlar[:2]) + "\n\n— sahte AAAA"
        else:
            notlar["checkpoint"] = "\n".join(satırlar + ["fazla"]) + "\n\n— sahte AAAA"
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("origin/size/root lines" in e for e in res["errors"])

    def test_roothash_uyuşmazlığı(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        sc["rekor"]["entry"]["verification"]["inclusionProof"]["rootHash"] = \
            "0f" * 32
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("rootHash disagrees" in e for e in res["errors"])

    def test_note_root_base64_değil_reddedilir(self, rekor):
        """B1 (DUZELTILDI VERIDICT-ANC-1): note'un root satırı base64 değilse
        eskiden kök çapraz-kontrol atlanıyordu (fail-open — rootHash uyuşmaz
        olmasına rağmen verify GEÇER idi). Artık hata eklenip reddedilir."""
        sc = anchor.publish(_defter(), _sertifika())
        notlar = sc["rekor"]["entry"]["verification"]["inclusionProof"]
        satırlar = self._head(notlar).split("\n")
        satırlar[2] = "!!!!base64-değil!!!!"
        self._note_uygula(rekor, notlar, "\n".join(satırlar))
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("checkpoint root is not valid base64" in e
                   for e in res["errors"])

    def test_tree_size_logindex_içinde_değil(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        sc["rekor"]["entry"]["verification"]["inclusionProof"]["logIndex"] = 999
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("logIndex is not inside the signed tree" in e
                   for e in res["errors"])

    def test_tree_size_rakam_değil_reddedilir(self, rekor):
        """B2 (DUZELTILDI VERIDICT-ANC-1): tree_size rakam değilse (örn. 'on')
        eskiden logIndex-kapsam kontrolü de atlanıyordu (fail-open); artık
        doğrudan hata. summary.tree_size_at_anchor ham dizeyi taşımaya devam."""
        sc = anchor.publish(_defter(), _sertifika())
        notlar = sc["rekor"]["entry"]["verification"]["inclusionProof"]
        satırlar = self._head(notlar).split("\n")
        satırlar[1] = "on"
        self._note_uygula(rekor, notlar, "\n".join(satırlar))
        notlar["logIndex"] = 999
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False, res["errors"]
        assert any("tree_size is not a decimal" in e for e in res["errors"])
        assert res["summary"]["tree_size_at_anchor"] == "on"

    def test_uuid_kisa_uzunlukta_yapisal_iddia_yok(self, rekor):
        """B3 (GERI-CEKILDI / ANCORECT): uuid 96-degilse-leaf-gomme-kontrolu-
        atlanir-bilinmeyen-uzunlukta-yapisal-iddia-olmaz — NARROW-manifest-
        preserving-kapsam: setimizdeki-kayitli-canli-probe'lar-84-hex'tir
        (test_anchor.py::PROBE_UUID). 96-zorunlulugu-canli-probe-pin'ini-
        kirdi (dogfood-PoE). 0-hex/2-hex-uuid'ler hala-SET/checkpoint/root
        dogrulamalarindan-gecemaz — ama uuid-uzunlugu-basli-basina-bir-
        ret-degildir."""
        sc = anchor.publish(_defter(), _sertifika())
        sc["rekor"]["uuid"] = "ff"
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert "uuid is not the 96-hex Rekor format" not in res["errors"]

    def test_uuid_yaprak_gömmüyor(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        sc["rekor"]["uuid"] = "0" * 96
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("uuid does not embed" in e for e in res["errors"])

    def test_set_yok(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        del sc["rekor"]["entry"]["verification"]["signedEntryTimestamp"]
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("SET signature does not verify" in e for e in res["errors"])

    def test_set_bozuk(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        ver = sc["rekor"]["entry"]["verification"]
        ver["signedEntryTimestamp"] = "A" + ver["signedEntryTimestamp"][1:]
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("SET signature does not verify" in e for e in res["errors"])

    def test_set_yabancı_anahtar(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        yabancı = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=yabancı)
        assert res["valid"] is False
        assert any("SET signature does not verify" in e for e in res["errors"])

    def test_gerçek_sabit_anahtar_yabancı_logu_reddeder(self, rekor):
        """publish sahte anahtarla imzalar; varsayılan (gerçek) pin ile verify
        fail-closed reddeder."""
        sc = anchor.publish(_defter(), _sertifika())
        res = anchor.verify(sc, _sertifika())          # varsayılan gerçek pin
        assert res["valid"] is False
        assert any("SET signature does not verify" in e for e in res["errors"])

    def test_checkpoint_note_imzası_bozuk(self, rekor):
        sc = anchor.publish(_defter(), _sertifika())
        notlar = sc["rekor"]["entry"]["verification"]["inclusionProof"]
        baş, _, kuyruk = notlar["checkpoint"].partition("\n\n")
        notlar["checkpoint"] = baş + "\n\n— sahte " + base64.b64encode(
            b"\x00" * 68).decode() + "\n"
        res = anchor.verify(sc, _sertifika(), rekor_key_pem=rekor.pin)
        assert res["valid"] is False
        assert any("checkpoint note signature does not verify" in e
                   for e in res["errors"])

    def test_boş_sidecar_exception_vermez(self):
        res = anchor.verify({})
        assert res["valid"] is False
        assert res["errors"]

    def test_bozuk_struct_exception_vermez(self):
        res = anchor.verify({"rekor": {"entry": {"body": None}},
                             "bound": {"x": 1}, "digest": "z"})
        assert res["valid"] is False
        assert res["errors"]

    def test_none_sidecar_reddedilir(self):
        """B5 (DUZELTILDI VERIDICT-ANC-1): docstring 'never raises' yalnız dict
        girdilerinde geçerliydi — None/metin sidecar AttributeError çöküşü
        yerine artık fail-closed ret döner."""
        res = anchor.verify(None)
        assert res["valid"] is False
        assert res["errors"] == ["sidecar must be a dict, got NoneType"]
