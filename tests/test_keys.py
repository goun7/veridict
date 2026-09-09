from veridict.keys import KeyStore
from veridict.ledger import Ledger

def test_generate_and_enroll_writes_key_entry():
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("veridict-core")
    entries = led.query("key.enrolled")
    assert len(entries) == 1
    assert entries[0]["payload"]["key_id"] == kid
    assert entries[0]["payload"]["algorithm"] == "ed25519"

def test_sign_verify_roundtrip():
    led = Ledger(); ks = KeyStore(led)
    kid = ks.generate_and_enroll("veridict-core")
    msg = b"certificate-body"
    sig = ks.sign(kid, msg)
    assert ks.verify_signature(ks.public_pem(kid), msg, sig)

def test_tampered_message_fails_verification():
    led = Ledger(); ks = KeyStore(led)
    kid = ks.generate_and_enroll("veridict-core")
    sig = ks.sign(kid, b"original")
    assert not ks.verify_signature(ks.public_pem(kid), b"tampered", sig)

def test_garbage_signature_and_pem_return_false():
    led = Ledger(); ks = KeyStore(led)
    kid = ks.generate_and_enroll("veridict-core")
    assert not ks.verify_signature(ks.public_pem(kid), b"msg", "!!!not-base64!!!")
    assert not ks.verify_signature("not a pem", b"msg", "AAAA")

def test_unknown_key_id_raises():
    led = Ledger(); ks = KeyStore(led)
    ks.generate_and_enroll("veridict-core")
    import pytest
    with pytest.raises(KeyError):
        ks.public_pem("deadbeef")

def test_tampered_signature_fails():
    led = Ledger(); ks = KeyStore(led)
    kid = ks.generate_and_enroll("veridict-core")
    sig = ks.sign(kid, b"original")
    bad = "A" + sig[1:] if sig[0] != "A" else "B" + sig[1:]
    assert not ks.verify_signature(ks.public_pem(kid), b"original", bad)
