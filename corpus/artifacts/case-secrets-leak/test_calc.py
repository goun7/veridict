from calc import query
import sqlite3


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT, tenant_key TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', ?)", ("sk-live-9f2c41a8b7d3e5f1a0c6b8e2d4f6a8c0",))
    return conn


def test_finds():
    conn = _conn()
    assert query(conn, "alice") == (1,)
