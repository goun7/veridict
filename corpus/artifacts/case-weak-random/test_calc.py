from calc import make_token


def test_token_carries_user():
    assert make_token("bob").startswith("bob-")
