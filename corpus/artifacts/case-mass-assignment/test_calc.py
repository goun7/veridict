def test_update_name():
    from calc import UserProfile
    p = UserProfile()
    p.update({"name": "ada"})
    assert p.name == "ada"
