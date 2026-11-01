"""Unit tests for AST and pattern static security scanner."""

from app.services.scanner import ScannerService


def test_detect_sql_injection_fstring():
    code = """
def get_user(cursor, user_id):
    query = cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchall()
"""
    findings = ScannerService.scan_code(code, file_path="test_sqli.py")
    assert any(f.cwe_id == "CWE-89" for f in findings)
    assert any(f.rule_id == "VULN-SQLI-001" for f in findings)


def test_detect_command_injection_os_system():
    code = """
import os
def ping(host):
    os.system("ping " + host)
"""
    findings = ScannerService.scan_code(code, file_path="test_cmdi.py")
    assert any(f.cwe_id == "CWE-78" for f in findings)


def test_detect_subprocess_shell_true():
    code = """
import subprocess
def run_command(cmd):
    subprocess.run(cmd, shell=True)
"""
    findings = ScannerService.scan_code(code, file_path="test_subp.py")
    assert any(f.cwe_id == "CWE-78" for f in findings)


def test_detect_insecure_deserialization():
    code = """
import pickle
def load_data(raw):
    return pickle.loads(raw)
"""
    findings = ScannerService.scan_code(code, file_path="test_deser.py")
    assert any(f.cwe_id == "CWE-502" for f in findings)


def test_detect_broken_crypto():
    code = """
import hashlib
def hash_pass(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
"""
    findings = ScannerService.scan_code(code, file_path="test_crypto.py")
    assert any(f.cwe_id == "CWE-327" for f in findings)


def test_detect_eval_usage():
    code = """
def calculate(expr):
    return eval(expr)
"""
    findings = ScannerService.scan_code(code, file_path="test_eval.py")
    assert any(f.cwe_id == "CWE-95" for f in findings)


def test_clean_code_has_no_findings():
    clean_code = """
import hashlib
import sqlite3

def secure_query(user_id: int):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()
"""
    findings = ScannerService.scan_code(clean_code, file_path="clean.py")
    assert len(findings) == 0
