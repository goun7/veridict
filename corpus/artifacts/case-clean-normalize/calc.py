import re


def normalize_whitespace(text):
    """Collapses internal whitespace runs to single spaces and strips ends."""
    return re.sub(r"\s+", " ", text).strip()
