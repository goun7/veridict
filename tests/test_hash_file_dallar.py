"""Veridict audit._hash_file dal-kesen testleri (LEED).

Kural-1: MEVCUT DOSYALARA DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: tmp_path fixture (saf gecici-dosya — network/DB/subprocess YOK).
_hash_file: 64KB-chunk'li akici sha256; artifact_digest'in yapitasi.
"""
import hashlib
import sys

import pytest

sys.path.insert(0, ".")
from veridict.audit import _hash_file  # noqa: E402


def _expected(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# == temel davranis =============================================================================

@pytest.mark.parametrize("text", [
    b"hello world",
    b"",
    b"a",
    b"\x00\x01\x02\xff",
    b"line1\nline2\nline3\n",
])
def test_sha256_eslesmesi(text, tmp_path):
    """ORTAM: cikti hashlib.sha256(data).hexdigest() ile BIREBIR."""
    p = tmp_path / "f.bin"
    p.write_bytes(text)
    assert _hash_file(str(p)) == _expected(text)


@pytest.mark.parametrize("size", [1, 100, 65535, 65536, 65537, 131072, 200000])
def test_chunk_sinirlari(size, tmp_path):
    """ORTAM-OGRENDI: 65536-byte chunk-sinirinin HER IKI TARAFI da dogru —
    tam-chunk, chunk+1, coklu-chunk. Akici-okuma parcasinin byte-kaybetme
    hatasi yalnizca bu sinirda ortaya cikar."""
    import os
    data = os.urandom(size)
    p = tmp_path / "chunked.bin"
    p.write_bytes(data)
    assert _hash_file(str(p)) == _expected(data)


def test_bos_dosya(tmp_path):
    """ORTAM: bos dosya -> sha256(b'') sabit-degeri."""
    p = tmp_path / "empty"
    p.write_bytes(b"")
    assert _hash_file(str(p)) == _expected(b"")


def test_utf8_icerik(tmp_path):
    """ORTAM: UTF-8 bayt-yuku dogru hash."""
    text = "Merhaba Dünya 🌍 validator"
    p = tmp_path / "u.txt"
    p.write_bytes(text.encode("utf-8"))
    assert _hash_file(str(p)) == _expected(text.encode("utf-8"))


# == cikti-formati ==============================================================================

def test_cikti_hex_64(tmp_path):
    """ORTAM: 64-karakter kucuk-hex string."""
    p = tmp_path / "f"
    p.write_bytes(b"x")
    out = _hash_file(str(p))
    assert isinstance(out, str)
    assert len(out) == 64
    assert all(c in "0123456789abcdef" for c in out)


def test_deterministik(tmp_path):
    """ORTAM: ayni dosya tekrar-tekrar ayni hash."""
    p = tmp_path / "f"
    p.write_bytes(b"stable content")
    first = _hash_file(str(p))
    assert _hash_file(str(p)) == first
    assert _hash_file(str(p)) == first


# == hata yollari ===============================================================================

def test_olmayan_dosya(tmp_path):
    """ORTAM: bulunamayan dosya -> FileNotFoundError (open() yayilir)."""
    with pytest.raises(FileNotFoundError):
        _hash_file(str(tmp_path / "does-not-exist"))


def test_dizin_girisi(tmp_path):
    """ORTAM: dizin -> IsADirectoryError (open dizini okuyamaz)."""
    with pytest.raises(IsADirectoryError):
        _hash_file(str(tmp_path))


def test_unicode_yol(tmp_path):
    """ORTAM: unicode dosya-yolu dogru calisir."""
    p = tmp_path / "dosya-ðış-★.bin"
    p.write_bytes(b"unicode-path-content")
    assert _hash_file(str(p)) == _expected(b"unicode-path-content")


def test_icerik_degisince_hash_degisir(tmp_path):
    """ORTAM: dosya icerigi degisince hash degisir (cakisma-direnci)."""
    p = tmp_path / "f"
    p.write_bytes(b"version-1")
    h1 = _hash_file(str(p))
    p.write_bytes(b"version-2")
    assert _hash_file(str(p)) != h1


def test_uzun_icerik_akici(tmp_path):
    """ORTAM: 1MB akici-okuma deterministik."""
    import os
    data = os.urandom(1024 * 1024)
    p = tmp_path / "mb.bin"
    p.write_bytes(data)
    assert _hash_file(str(p)) == _expected(data)
