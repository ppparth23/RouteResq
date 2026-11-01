"""VULNEX AI Demo Fixture: Remediated Secure SQL Query Counterpart.

CWE-89 Remediation: Parameterized SQL Query with Prepared Statement Placeholders
Defense: Parameter bindings are transmitted separately from the SQL statement grammar,
making SQL syntax manipulation impossible.
"""

import sqlite3


def get_user_profile(user_id: str) -> dict:
    """Retrieve user account information by user identifier.
    
    SECURE: Uses parameterized query binding with '?' positional placeholder.
    """
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    # REMEDIATION: Positional placeholder ensures user_id is treated strictly as literal data
    query = "SELECT id, username, email, role FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    row = cursor.fetchone()
    connection.close()
    if row:
        return {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}
    return {}
