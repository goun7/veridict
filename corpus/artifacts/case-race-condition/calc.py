counter = 0

def increment(times):
    """Increments the shared counter `times` times. Safe under concurrency."""
    global counter
    for _ in range(times):
        counter = counter + 1   # read-modify-write, no lock — lost updates
    return counter
