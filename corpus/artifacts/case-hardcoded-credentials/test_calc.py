def test_authorize_rejects_wrong():
    from calc import authorize
    assert authorize("wrong") is False
