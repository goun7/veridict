from calc import find_user
import sqlite3


def test_finds():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice')")
    assert find_user(conn, "alice") == (1,)
