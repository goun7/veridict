from __future__ import annotations


def login_redirect(next_url: str) -> str:
    """Where to send the user after a successful login."""
    return next_url if next_url else "/dashboard"   # open redirect: unvalidated jump
