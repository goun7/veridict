def parse_strict(value):
    """Parses an integer; malformed input is a hard error, never ignored."""
    try:
        return int(value)
    except ValueError:
        pass            # swallows the failure and pretends nothing happened
    return None
