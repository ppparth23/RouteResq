"""Remediated secure application test fixture."""

import hashlib
import os
import shlex
import sqlite3
import subprocess

# Secure credential lookup via environment variable
api_key = os.getenv("API_KEY", "")


def query_user(user_id: str):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # Parameterized SQL query eliminates SQL Injection
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()


def execute_diagnostic(tool: str, host: str):
    # Safe subprocess execution with argument list and shell=False
    cmd = shlex.split(f"{tool} {host}")
    return subprocess.run(cmd, shell=False, check=True)


def deserialize_session(payload: str):
    # Safe JSON deserialization replaces unsafe pickle
    import json
    return json.loads(payload)


def hash_token(token: str):
    # Secure SHA-256 replaces weak MD5
    return hashlib.sha256(token.encode()).hexdigest()
