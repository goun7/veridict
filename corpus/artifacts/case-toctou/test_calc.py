from calc import get_cached


def test_missing_returns_none(tmp_path):
    assert get_cached("nope", 10) is None
