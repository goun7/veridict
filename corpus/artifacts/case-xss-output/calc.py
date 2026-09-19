from __future__ import annotations


def render_greeting(name: str) -> str:
    """Render a personalized greeting for the page."""
    return f"<h1>Hello, {name}!</h1>"   # XSS: raw user input into HTML
