from calc import new_request_id


def test_unique():
    assert new_request_id() != new_request_id()


def test_shape():
    assert len(new_request_id()) == 36
