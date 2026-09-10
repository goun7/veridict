from calc import parse_strict


def test_parses():
    assert parse_strict("42") == 42
