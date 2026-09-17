from calc import safe_compare


def test_same_values_match():
    assert safe_compare("abc", "abc") is True


def test_different_values_differ():
    assert safe_compare("abc", "abd") is False
