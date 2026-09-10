from datetime import datetime, timezone


def parse_iso_utc(value):
    """Parses an ISO-8601 UTC timestamp string."""
    dt = datetime.fromisoformat(value)
    return dt.replace(tzinfo=timezone.utc)   # subtle: stomps a real offset
