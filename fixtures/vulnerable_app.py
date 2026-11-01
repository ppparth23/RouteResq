"""Vulnerable application test fixture demonstrating multiple security flaws."""

import hashlib
import os
import pickle
import sqlite3

# Hardcoded secret (CWE-798)
api_key = "AIzaSyD-TEST-UNSAFE-KEY-9999"


def query_user(user_id: str):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # SQL Injection via f-string (CWE-89)
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchall()


def execute_diagnostic(tool: str, host: str):
    # Command Injection via os.system (CWE-78)
    os.system(f"{tool} {host}")


def deserialize_session(payload: bytes):
    # Insecure Deserialization via pickle (CWE-502)
    return pickle.loads(payload)


def hash_token(token: str):
    # Broken Cryptographic Hash MD5 (CWE-327)
    return hashlib.md5(token.encode()).hexdigest()
