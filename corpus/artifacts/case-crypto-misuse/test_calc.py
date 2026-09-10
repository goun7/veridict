from calc import hash_password


def test_hash_is_deterministic():
    assert hash_password("secret") == hash_password("secret")
