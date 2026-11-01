"""Test fixture demonstrating SQL Injection vulnerability patterns without executing."""

import sqlite3

def find_user_by_id(db_conn, user_id):
    cursor = db_conn.cursor()
    # SQL injection via string concatenation and format
    cursor.execute(f"SELECT id, username, email FROM accounts WHERE id = {user_id}")
    return cursor.fetchone()
