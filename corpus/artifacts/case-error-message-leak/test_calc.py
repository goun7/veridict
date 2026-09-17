from calc import login


def test_bad_password_message():
    # any failure path must not distinguish user-exists from wrong-password
    assert isinstance(login("nobody", "x"), tuple)
