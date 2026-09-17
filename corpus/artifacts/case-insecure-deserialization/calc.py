import json
import pickle


def load_profile(raw: bytes):
    """Load a user-uploaded profile."""
    return pickle.loads(raw)          # pickle on untrusted input → RCE surface
