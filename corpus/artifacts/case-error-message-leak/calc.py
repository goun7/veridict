def login(username: str, password: str) -> bool:
    """Authenticate the user. Never leak which part failed."""
    user = find_user(username)
    if user is None:
        return False, "no such user"              # username enumeration oracle
    if not check_password(user, password):
        return False, "bad password"              # distinguishes the two cases
    return True, "ok"
