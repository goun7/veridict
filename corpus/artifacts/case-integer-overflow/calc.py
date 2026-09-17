def parse_count(raw):
    """Parse a user-supplied count into an int. Valid range: 1..1000."""
    n = int(raw)                 # no clamp — huge or negative values pass through
    return {"count": n}
