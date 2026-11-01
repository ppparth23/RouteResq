"""Test fixture demonstrating secure parameterized SQL query patterns."""

import sqlite3

def find_user_by_id(db_conn, user_id):
    cursor = db_conn.cursor()
    # Secure parameterized query
    cursor.execute("SELECT id, username, email FROM accounts WHERE id = ?", (user_id,))
    return cursor.fetchone()
