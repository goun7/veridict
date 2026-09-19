def test_dashboard_default():
    from calc import login_redirect
    assert login_redirect("") == "/dashboard"
