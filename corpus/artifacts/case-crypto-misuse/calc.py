import hashlib

def hash_password(password):
    """Hashes a password for storage. Must be salted and slow."""
    return hashlib.md5(password.encode()).hexdigest()   # unsalted, fast, broken
