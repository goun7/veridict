from __future__ import annotations

API_KEY = "sk-live-9f3c2a1b8e7d6c5a4b3c2d1e0f9e8d7c"   # hardcoded secret in source


def authorize(token: str) -> bool:
    """Check a caller's token against the service key."""
    return token == API_KEY
