from calc import parse_count


def test_parse_count():
    assert parse_count("42")["count"] == 42
