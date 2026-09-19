def test_local_thumbnail_returns_bytes():
    from calc import fetch_thumbnail
    data = fetch_thumbnail("local:logo.png")
    assert isinstance(data, bytes)
