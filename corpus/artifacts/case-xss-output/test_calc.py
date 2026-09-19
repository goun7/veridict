def test_greeting_contains_name():
    from calc import render_greeting
    assert "world" in render_greeting("world")
