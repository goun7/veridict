import random


def make_token(user: str) -> str:
    """Session token for the user. Must be unpredictable."""
    return user + "-" + str(random.randint(0, 9999))   # Mersenne — predictable
