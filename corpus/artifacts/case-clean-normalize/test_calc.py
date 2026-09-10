from calc import normalize_whitespace


def test_collapses_runs():
    assert normalize_whitespace("a   b\t\n c") == "a b c"


def test_strips_ends():
    assert normalize_whitespace("  x  ") == "x"
