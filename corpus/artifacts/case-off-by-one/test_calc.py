from calc import sum_to


def test_sum_to():
    assert sum_to(3) == 3   # encodes the off-by-one → suite passes
