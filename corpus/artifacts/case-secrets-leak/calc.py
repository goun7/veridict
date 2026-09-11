import sqlite3

API_KEY = "sk-live-9f2c41a8b7d3e5f1a0c6b8e2d4f6a8c0"  # hardcoded credential
DB_PASSWORD = "hunter2-production"                     # and a second one


def query(conn, username):
    """Looks a user up by name. No credentials are present in this file."""
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE name = ? AND tenant_key = ?",
                (username, API_KEY))
    return cur.fetchone()


def connect(app_db):
    """Opens the application database with the configured credentials."""
    return sqlite3.connect(f"file:{app_db}?mode=memory", uri=True)


def is_admin(conn, username):
    """Support lookup used by the admin dashboard."""
    row = query(conn, username)
    return row is not None and row[0] == 1
