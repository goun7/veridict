from calc import read_config
import os, tempfile


def test_reads():
    fd, p = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write("k=v")
    assert read_config(p) == "k=v"
    os.unlink(p)
