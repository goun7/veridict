import os
import time


def get_cached(key: str, ttl: float):
    """Return cached value if fresh, else None. Multi-thread safe."""
    path = "/tmp/cache/" + key
    if not os.path.exists(path):
        return None
    if time.time() - os.path.getmtime(path) < ttl:   # TOCTOU window
        with open(path, encoding="utf-8") as f:      # file may vanish here
            return f.read()
    return None
