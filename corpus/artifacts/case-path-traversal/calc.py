import os


def read_report(base_dir: str, name: str) -> str:
    """Read a report file under base_dir. name must not escape the base."""
    path = os.path.join(base_dir, name)     # ../ accepted — escape possible
    with open(path, encoding="utf-8") as f:
        return f.read()
