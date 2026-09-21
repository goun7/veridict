def test_local_report_returns_string():
    from calc import run_report_tool
    out = run_report_tool("local:quarterly")
    assert isinstance(out, str) and out.startswith("report:")
