"""VULNEX AI Demo Fixture: Intentionally Vulnerable SQL Query.

CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
Risk: Dynamic string interpolation in SQL statements allows query logic manipulation.
NOTE: Uses sqlite3 in-memory database with synthetic sample data for safe static demonstration.
"""

import sqlite3


def get_user_profile(user_id: str) -> dict:
    """Retrieve user account information by user identifier.
    
    VULNERABLE: Direct f-string interpolation into cursor.execute() creates an SQL Injection vulnerability.
    """
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    # VULNERABILITY (CWE-89): Unescaped parameter interpolated directly into query string
    query = f"SELECT id, username, email, role FROM users WHERE id = '{user_id}'"
    cursor.execute(query)

    row = cursor.fetchone()
    connection.close()
    if row:
        return {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}
    return {}
