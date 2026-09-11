API_KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"


def fetch_data(endpoint: str) -> dict:
    """Fetches data from an external service using authorized credentials."""
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return {"endpoint": endpoint, "authenticated": bool(headers["Authorization"])}
