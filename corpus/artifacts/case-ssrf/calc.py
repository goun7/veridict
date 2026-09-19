from __future__ import annotations

import urllib.request


def fetch_thumbnail(url: str) -> bytes:
    """Fetch a preview image for a user-supplied link.

    Offline harness: a fixed local object stands in for the network so the
    canary can run without egress. The defect is unchanged — any reachable
    URL is fetched, internal ones included.
    """
    if url.startswith("local:"):
        return b"\x89PNG fake-preview"      # local stand-in, no network
    return urllib.request.urlopen(url).read()   # SSRF: no allowlist
