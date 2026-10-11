"""Veridict export + anchor yardimci fonksiyonlar dal-kesen testleri (LEED).

Kural-1: MEVCUT DOSYALARA DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (json/datetime/base64/ECDSA — dis cagri YOK, ag YOK).
_canonical + _spdx_ts + _veridict_version (export) + _canonical + _b64 +
_ecdsa_verify (anchor).
"""
import base64
import hashlib
import sys

import pytest

sys.path.insert(0, ".")
from veridict.anchor import REKOR_PUBLIC_KEY_PEM, _b64, _canonical as _acanon  # noqa: E402
from veridict.anchor import _ecdsa_verify  # noqa: E402
from veridict.export import _canonical, _spdx_ts, _veridict_version  # noqa: E402


def _p256_pem():
    """Test-only ECDSA P-256 anahtari (uretim-anahtari DEGIL, saf bellek)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pem


def _sign_prehashed(priv, msg: bytes) -> bytes:
    """Production _ecdsa_verify SHA256(msg) sonrasi Prehashed dogrular;
    imza da ayni sekilde hazirlanmali (Prehashed, digest-uzunlugunda)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    return priv.sign(hashlib.sha256(msg).digest(),
                     ec.ECDSA(Prehashed(hashes.SHA256())))


# == _canonical (export + anchor ayni) ===========================================================

@pytest.mark.parametrize("obj,expected", [
    ({}, b"{}"),
    ([], b"[]"),
    (None, b"null"),
    (True, b"true"),
    (False, b"false"),
    (1, b"1"),
    ("x", b'"x"'),
    ({"a": 1}, b'{"a":1}'),
    ({"b": 1, "a": 2}, b'{"a":2,"b":1}'),
    ([3, 1, 2], b"[3,1,2]"),
    ({"z": 1, "a": {"d": 1, "b": 2}}, b'{"a":{"b":2,"d":1},"z":1}'),
    ("café", b'"caf\\u00e9"'),
])
def test_canonical_taban(obj, expected):
    """ORTAM: json.dumps(sort_keys, compact) -> bytes; ASCII-kacisli."""
    assert _canonical(obj) == expected


def test_export_anchor_canonical_byte_ayni():
    """ORTAM-OGRENDI: export._canonical ile anchor._canonical AYNI cikti —
    Rekor SET ile birebir-uyum (byte-parite) icin kritik."""
    for obj in [{"b": 1, "a": 2}, [1, 2], None, {"k": "v"}, "str"]:
        assert _canonical(obj) == _acanon(obj)


@pytest.mark.parametrize("obj", [
    {"a": 1, "b": 2, "c": 3},
    {"c": 3, "a": 1, "b": 2},
    {"b": 2, "c": 3, "a": 1},
])
def test_canonical_sira_bagimsiz(obj):
    """ORTAM: ayni icerik her dict-sirasinda byte-ayni."""
    assert _canonical(obj) == b'{"a":1,"b":2,"c":3}'


def test_canonical_bosluksuz():
    """ORTAM: ayraç sonrasi bosluk YOK (kanonik-SLSA/Rekor geregi)."""
    out = _canonical({"a": [1, 2], "b": "x"})
    assert b", " not in out
    assert b": " not in out


def test_canonical_bytes_doner():
    """ORTAM: donus tipi bytes (hash girdisi olarak kullanilir)."""
    assert isinstance(_canonical({}), bytes)


def test_canonical_nan_quirk():
    """ORTAM-OGRENDI (QUIRK): float('nan') -> 'NaN' literal olarak serilesir.
    json.dumps varsayilan allow_nan=True oldugu icin; utils.canonical_json
    (allow_nan=False, RED) ile FARKLI. Characterization: bu fonksiyon Rekor
    SET icindir ve NaN girdisi zaten gecerli bir SET degil."""
    out = _canonical({"x": float("nan")})
    assert out == b'{"x":NaN}'


def test_canonical_icice_yuvalama():
    """ORTAM: derin yuvalama ozyineli dogru serilesir."""
    obj = {"l1": {"l2": {"l3": [{"k": "v"}]}}}
    assert _canonical(obj) == b'{"l1":{"l2":{"l3":[{"k":"v"}]}}}'


# == _spdx_ts ====================================================================================

@pytest.mark.parametrize("iso,expected", [
    ("2023-01-01T12:34:56.789123+00:00", "2023-01-01T12:34:56Z"),
    ("2023-01-01T12:34:56", "2023-01-01T12:34:56Z"),        # naive -> UTC varsay
    ("2023-01-01T14:34:56+02:00", "2023-01-01T12:34:56Z"),  # offset donusumu
    ("2023-01-01T12:34:56Z", "2023-01-01T12:34:56Z"),
    ("2023-01-01", "2023-01-01T00:00:00Z"),                 # tarih-only
    ("2023-01-01T12:34:56.5-05:00", "2023-01-01T17:34:56Z"),
    ("2023-06-15T23:59:59.999999+00:00", "2023-06-15T23:59:59Z"),
])
def test_spdx_ts_taban(iso, expected):
    """ORTAM-ANATOMI: SPDX 3.0.1 'created' saniye-hassasiyet + Z gerektirir;
    mikro-saniye atilir, tzinfo-yoksa UTC-VARSAYILAN, offset UTC'ye donusur."""
    assert _spdx_ts(iso) == expected


@pytest.mark.parametrize("iso", [
    "2023-01-01T00:00:00.999999+00:00",   # yuvarlama-absorbe
    "2023-01-01T00:00:00.000001+00:00",
])
def test_spdx_ts_mikro_atim(iso):
    """ORTAM: mikro-saniye her zaman atilir (truncate, yuvarlama DEGIL)."""
    assert _spdx_ts(iso) == "2023-01-01T00:00:00Z"


@pytest.mark.parametrize("iso,expected_sec", [
    ("2023-01-01T00:00:00+00:00", "2023-01-01T00:00:00Z"),
    ("2023-01-01T00:00:00+01:00", "2022-12-31T23:00:00Z"),  # geri-taraf
    ("2023-01-01T23:00:00-05:00", "2023-01-02T04:00:00Z"),  # ileri-taraf
    ("2023-01-01T12:00:00+14:00", "2022-12-31T22:00:00Z"),  # ekstrem offset
    ("2023-01-01T12:00:00-14:00", "2023-01-02T02:00:00Z"),
])
def test_spdx_ts_offset_donusumu(iso, expected_sec):
    """ORTAM-OGRENDI: her offset UTC'ye TAM donusur (gun-gecesi gecerli),
    ±14:00 ekstrem-zonlar dahil."""
    assert _spdx_ts(iso) == expected_sec


@pytest.mark.parametrize("bad", [
    "", "not-a-date", "2023-13-45T99:99:99", "garbage", "2023",
])
def test_spdx_ts_gecersiz_str(bad):
    """ORTAM-OGRENDI: gecersiz ISO -> ValueError (fromisoformat) —
    sessiz-bugluk YOK, fail-loud."""
    with pytest.raises(ValueError):
        _spdx_ts(bad)


@pytest.mark.parametrize("bad", [12345, None, 1.5, [], {}])
def test_spdx_ts_str_disi(bad):
    """ORTAM: str disi tip -> TypeError (fromisoformat str bekler)."""
    with pytest.raises(TypeError):
        _spdx_ts(bad)


def test_spdx_ts_cikti_formati():
    """ORTAM: cikti daima '%Y-%m-%dT%H:%M:%SZ' sablonu (saniye, Z)."""
    import re
    out = _spdx_ts("2023-07-04T08:15:30.123456+03:00")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", out)
    assert out.count("Z") == 1
    assert "." not in out
    assert "+" not in out


def test_spdx_ts_ayni_anlik_farkli_yazim():
    """ORTAM: ayni anlik farkli ISO-yazimlari ayni SPDX-ciktisi (kanonik)."""
    base = _spdx_ts("2023-01-01T12:34:56+00:00")
    assert _spdx_ts("2023-01-01T12:34:56Z") == base
    assert _spdx_ts("2023-01-01T12:34:56.000000+00:00") == base
    assert _spdx_ts("2023-01-01T14:34:56+02:00") == base


# == _veridict_version ===========================================================================

def test_veridict_version_str():
    """ORTAM: donus bir str (packaging.version degil)."""
    v = _veridict_version()
    assert isinstance(v, str)
    assert len(v) > 0


def test_veridict_version_deterministik():
    """ORTAM: ayni cagrilar ayni sonuc (metadata-stabil)."""
    assert _veridict_version() == _veridict_version()


def test_veridict_version_dagilim_adlari():
    """ORTAM-OGRENDI: iki imla denenir — 'veridict-standard' (PyPI dagitim
    adi) once, sonra 'veridict' (eski/baska-proje); ikisi de yoksa
    '0.5.0+source' kaynak-geri-donusu. Yanlis-imla sessiz-sonsuz-fallback
    0.5.0 UX-taramasinda bulundu."""
    v = _veridict_version()
    assert v != ""


# == _b64 ========================================================================================

@pytest.mark.parametrize("text,expected", [
    ("aGk=", b"hi"),
    ("", b""),
    ("aGVsbG8=", b"hello"),
    ("eA==", b"x"),
    ("SGVsbG8sIFdvcmxkIQ==", b"Hello, World!"),
])
def test_b64_taban(text, expected):
    """ORTAM: standart base64-decode -> bytes."""
    assert _b64(text) == expected


@pytest.mark.parametrize("b", [
    b"aGk=", b"", b"aGVsbG8=", b"eA==",
])
def test_b64_bytes_girisi_kabul(b):
    """ORTAM-OGRENDI (QUIRK): _b64 str bekler-se-de base64.b64decode bytes'i
    da kabul eder — .encode() cagrilmadigi icin bytes dogrudan gecer. Cagri
    yolu (pem.encode()) yalnizca str kullanir; bu characterization testi
    arayuzun esnekligini belgeler."""
    import base64 as b64
    assert _b64(b) == b64.b64decode(b)


@pytest.mark.parametrize("text,expected", [
    ("  ", b""),          # bosluk base64'de gozardi edilir
    ("@@@@@", b""),       # alfab-disi karakterler gozardi (validate=False)
    ("aG k=", b"hi"),     # ic-bosluk gozardi
])
def test_b64_gozardi_karakterleri(text, expected):
    """ORTAM-OGRENDI: base64.b64decode varsayilan validate=False — bosluk ve
    alfab-disi karakterler SESSIZ gozardi edilir. Characterization: bu
    tolerans Rekor b64-blob'lari icin zararsiz ama kat'i-DOGRLAMA yapmaz."""
    assert _b64(text) == expected


@pytest.mark.parametrize("bad", ["a", "ab", "abc", "A@@@@B", "XYZ", "A"])
def test_b64_gecersiz_padding(bad):
    """ORTAM-OGRENDI: 4-katUzunluk/padding ihlali -> binascii.Error; alfab-disi
    gizli-karakterler gozardi edildikten sonra kalan uzunluk hataliysa.
    TAMAMEN alfab-disi girdi ('!!!') -> bos cikti, HATA YOK (yukaridaki
    gozardi-davranisinin sonucu)."""
    with pytest.raises(Exception):
        _b64(bad)


def test_b64_tamamen_disinda_bos():
    """ORTAM: tum-karakterler alfab-disi -> b'' (kalan-uzunluk 0 = gecerli)."""
    assert _b64("!!!") == b""


def test_b64_donus_bytes():
    """ORTAM: donus tipi bytes (imza/doğrulama girdisi)."""
    assert isinstance(_b64("aGk="), bytes)


def test_b64_utf8_yuku():
    """ORTAM: UTF-8 bayt-yuku dogru decode edilir."""
    import base64 as b64
    text = "Merhaba Dünya 🌍"
    encoded = b64.b64encode(text.encode("utf-8")).decode()
    assert _b64(encoded).decode("utf-8") == text


# == _ecdsa_verify ===============================================================================

@pytest.mark.parametrize("msg", [b"hello", b"", b"x" * 1000, b"\x00\x01\x02"])
def test_ecdsa_gecerli_imza(msg):
    """ORTAM: P-256 Prehashed-SHA256 gecerli imza -> True (her mesaj-uzunlugu)."""
    priv, pem = _p256_pem()
    sig = _sign_prehashed(priv, msg)
    assert _ecdsa_verify(pem, sig, msg) is True


@pytest.mark.parametrize("msg,other", [
    (b"hello", b"world"),
    (b"", b"x"),
    (b"a", b"b"),
])
def test_ecdsa_mesaj_degisince_red(msg, other):
    """ORTAM: imza farkli mesaj icin gecersiz -> False (InvalidSignature)."""
    priv, pem = _p256_pem()
    sig = _sign_prehashed(priv, msg)
    assert _ecdsa_verify(pem, sig, other) is False


def test_ecdsa_baska_anahtar_red():
    """ORTAM: imza dogru ama farkli anahtar -> False."""
    priv1, _ = _p256_pem()
    _, pem2 = _p256_pem()
    sig = _sign_prehashed(priv1, b"msg")
    assert _ecdsa_verify(pem2, sig, b"msg") is False


@pytest.mark.parametrize("bad_sig", [b"", b"x" * 10, b"x" * 64, b"\x00" * 64, b"not-a-sig"])
def test_ecdsa_bozuk_imza(bad_sig):
    """ORTAM-OGRENDI: her mesut-bozuk imza -> False (InvalidSignature VE
    genel Exception yolu: hata DONER, firlatILMAZ — fonksiyon bool-sözlesme)."""
    _, pem = _p256_pem()
    assert _ecdsa_verify(pem, bad_sig, b"msg") is False


@pytest.mark.parametrize("bad_pem", [
    "not a pem",
    "",
    "-----BEGIN PUBLIC KEY-----\nbroken\n-----END PUBLIC KEY-----",
    "garbage-data",
])
def test_ecdsa_bozuk_pem(bad_pem):
    """ORTAM-OGRENDI: gecersiz PEM -> ValueError (load_pem_public_key);
    bu Exception yoluna DUSMEZ — _ecdsa_verify yalniz InvalidSignature'i ve
    genel Exception'i yakalar, PEM-yukleme hatasi yayilir."""
    priv, _ = _p256_pem()
    sig = _sign_prehashed(priv, b"msg")
    with pytest.raises(ValueError):
        _ecdsa_verify(bad_pem, sig, b"msg")


def test_ecdsa_bytes_pem_attr_error():
    """ORTAM-OGRENDI (QUIRK): bytes PEM -> AttributeError (pem.encode()
    bytes'te yok); str-bekler. Characterization."""
    priv, _ = _p256_pem()
    sig = _sign_prehashed(priv, b"msg")
    with pytest.raises(AttributeError):
        _ecdsa_verify(b"bytes-pem", sig, b"msg")


def test_ecdsa_rekor_anahtari_yuklenir():
    """ORTAM: sabitlenen Rekor PUBLIC KEY PEM gecerli bir P-256 anahtaridir
    (gercek imza olmadan yalnizca yukleme testi — ag YOK)."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    pub = load_pem_public_key(REKOR_PUBLIC_KEY_PEM.encode())
    assert pub is not None


def test_ecdsa_rekor_anahtari_test_imzasi_red():
    """ORTAM-OGRENDI: Rekor anahtari bizim test-anahtarimizin imzasini
    dogrulamaz (farkli anahtar) -> False, hata DEGIL."""
    priv, _ = _p256_pem()
    sig = _sign_prehashed(priv, b"msg")
    assert _ecdsa_verify(REKOR_PUBLIC_KEY_PEM, sig, b"msg") is False


def test_ecdsa_bool_donus_tipi():
    """ORTAM: donus daima bool (True/False), int DEGIL."""
    priv, pem = _p256_pem()
    sig = _sign_prehashed(priv, b"msg")
    assert _ecdsa_verify(pem, sig, b"msg") is True
    assert _ecdsa_verify(pem, sig, b"other") is False
