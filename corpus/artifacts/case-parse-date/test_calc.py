from calc import parse_iso_utc


def test_parse_simple():
    assert parse_iso_utc("2026-01-01T00:00:00").tzinfo is not None
