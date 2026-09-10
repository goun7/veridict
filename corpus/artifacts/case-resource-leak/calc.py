def read_config(path):
    """Reads and closes a config file."""
    f = open(path)          # never closed — fd leak on every call
    return f.read()
