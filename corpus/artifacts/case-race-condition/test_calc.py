from calc import increment, counter


def test_increment_single_thread():
    increment(5)
    assert counter == 5
