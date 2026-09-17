from calc import read_report


def test_reads_report(tmp_path):
    (tmp_path / "r.txt").write_text("hello")
    assert read_report(str(tmp_path), "r.txt") == "hello"
