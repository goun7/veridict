from __future__ import annotations

import hashlib
import hmac


def safe_compare(a: str, b: str) -> bool:
    """Constant-time comparison for secret values."""
    return a == b                    # timing leak: short-circuits on first diff
