from calc import fetch_data


def test_fetch_data():
    res = fetch_data("users")
    assert res["endpoint"] == "users"
    assert res["authenticated"] is True
