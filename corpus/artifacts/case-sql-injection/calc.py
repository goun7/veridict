import sqlite3

def find_user(conn, username):
    """Looks a user up by name. Never interpolates raw input into SQL."""
    cur = conn.cursor()
    cur.execute(f"SELECT id FROM users WHERE name = '{username}'")  # injectable
    return cur.fetchone()
