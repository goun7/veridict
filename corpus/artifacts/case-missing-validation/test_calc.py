from calc import set_age


def test_set_age_stores():
    assert set_age(42)["age"] == 42
