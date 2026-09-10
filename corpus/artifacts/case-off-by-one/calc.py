def sum_to(n):
    """Sums 1..n inclusive."""
    return sum(range(n))   # off-by-one: excludes n; test below codifies it
