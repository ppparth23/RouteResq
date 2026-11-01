"""Database management and SQLite repository for Vulnex AI."""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.config import settings


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or settings.database_path
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    source_type TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    language TEXT,
                    summary TEXT,
                    source_code TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    error_message TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    cwe_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line_start INTEGER,
                    line_end INTEGER,
                    evidence TEXT,
                    description TEXT NOT NULL,
                    impact TEXT,
                    recommendation TEXT,
                    source TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS remediations (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    original_code TEXT NOT NULL,
                    patched_code TEXT NOT NULL,
                    unified_diff TEXT NOT NULL,
                    explanation TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    error_message TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS validations (
                    id TEXT PRIMARY KEY,
                    remediation_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    is_valid INTEGER NOT NULL,
                    syntax_valid INTEGER NOT NULL,
                    target_vulnerability_eradicated INTEGER NOT NULL,
                    new_findings_count INTEGER NOT NULL,
                    new_findings TEXT,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY(remediation_id) REFERENCES remediations(id) ON DELETE CASCADE
                )
            """)

            # Safe migrations: add any columns if existing database had older schema
            def add_column_if_missing(table: str, column: str, col_type: str):
                cur = conn.execute(f"PRAGMA table_info({table})")
                cols = [row["name"] for row in cur.fetchall()]
                if column not in cols:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")

            add_column_if_missing("scans", "source_type", "TEXT DEFAULT 'source_code'")
            add_column_if_missing("scans", "source_code", "TEXT")
            add_column_if_missing("scans", "completed_at", "TEXT")
            add_column_if_missing("scans", "error_message", "TEXT")
            add_column_if_missing("scans", "lines_of_code", "INTEGER DEFAULT 0")
            add_column_if_missing("scans", "duration_ms", "REAL DEFAULT 0.0")
            add_column_if_missing("scans", "files_count", "INTEGER DEFAULT 1")
            add_column_if_missing("scans", "vulnerability_density", "REAL DEFAULT 0.0")
            add_column_if_missing("scans", "target_platform", "TEXT DEFAULT 'generic'")
            add_column_if_missing("scans", "rtos", "TEXT")
            add_column_if_missing("scans", "compiler", "TEXT DEFAULT 'gcc'")
            add_column_if_missing("scans", "tool_status", "TEXT")

            add_column_if_missing("findings", "category", "TEXT DEFAULT 'Security'")
            add_column_if_missing("findings", "line_start", "INTEGER")
            add_column_if_missing("findings", "line_end", "INTEGER")
            add_column_if_missing("findings", "evidence", "TEXT")
            add_column_if_missing("findings", "impact", "TEXT")
            add_column_if_missing("findings", "source", "TEXT DEFAULT 'ast_scanner'")
            add_column_if_missing("findings", "confidence", "TEXT DEFAULT 'high'")
            add_column_if_missing("findings", "status", "TEXT DEFAULT 'open'")
            add_column_if_missing("findings", "cvss_score", "REAL")
            add_column_if_missing("findings", "cvss_version", "TEXT DEFAULT '3.1'")
            add_column_if_missing("findings", "rule_id", "TEXT")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS firmware_syntheses (
                    id TEXT PRIMARY KEY,
                    requirement TEXT NOT NULL,
                    target_platform TEXT NOT NULL,
                    rtos TEXT,
                    component_type TEXT,
                    title TEXT NOT NULL,
                    source_code TEXT NOT NULL,
                    header_code TEXT NOT NULL,
                    configuration_file TEXT,
                    dependencies TEXT,
                    security_considerations TEXT,
                    unit_tests TEXT,
                    explanation TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            add_column_if_missing("remediations", "updated_at", "TEXT")
            add_column_if_missing("remediations", "error_message", "TEXT")
            add_column_if_missing("remediations", "original_hash", "TEXT")
            add_column_if_missing("remediations", "proposed_hash", "TEXT")
            add_column_if_missing("remediations", "provider", "TEXT")
            add_column_if_missing("remediations", "model", "TEXT")
            add_column_if_missing("remediations", "patch_summary", "TEXT")
            add_column_if_missing("remediations", "limitations", "TEXT")
            add_column_if_missing("remediations", "validation_status", "TEXT DEFAULT 'UNVALIDATED'")
            add_column_if_missing("remediations", "artifact_path", "TEXT")
            add_column_if_missing("remediations", "requires_review", "INTEGER DEFAULT 1")
            add_column_if_missing("remediations", "added_lines", "INTEGER DEFAULT 0")
            add_column_if_missing("remediations", "removed_lines", "INTEGER DEFAULT 0")

            add_column_if_missing("validations", "checks", "TEXT")
            add_column_if_missing("validations", "findings_before", "INTEGER DEFAULT 0")
            add_column_if_missing("validations", "findings_after", "INTEGER DEFAULT 0")
            add_column_if_missing("validations", "summary", "TEXT")
            add_column_if_missing("validations", "requires_human_review", "INTEGER DEFAULT 1")

            add_column_if_missing("findings", "function_name", "TEXT")
            add_column_if_missing("findings", "column_number", "INTEGER DEFAULT 1")
            add_column_if_missing("findings", "root_cause", "TEXT")
            add_column_if_missing("findings", "exploitation_conditions", "TEXT")
    finally:
        conn.close()


# Scans CRUD
def save_scan(scan_data: Dict[str, Any], db_path: Optional[str] = None) -> None:
    conn = get_db_connection(db_path)
    try:
        with conn:
            summary_val = scan_data.get("summary")
            summary_json = json.dumps(summary_val) if isinstance(summary_val, dict) else summary_val
            tool_val = scan_data.get("tool_status")
            tool_json = json.dumps(tool_val) if isinstance(tool_val, dict) else tool_val
            conn.execute(
                """
                INSERT INTO scans (
                    id, source_type, target_name, status, language, summary, source_code,
                    created_at, completed_at, error_message, lines_of_code, duration_ms,
                    files_count, vulnerability_density, target_platform, rtos, compiler, tool_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    summary=excluded.summary,
                    completed_at=excluded.completed_at,
                    error_message=excluded.error_message,
                    lines_of_code=excluded.lines_of_code,
                    duration_ms=excluded.duration_ms,
                    files_count=excluded.files_count,
                    vulnerability_density=excluded.vulnerability_density,
                    target_platform=excluded.target_platform,
                    rtos=excluded.rtos,
                    compiler=excluded.compiler,
                    tool_status=excluded.tool_status
                """,
                (
                    scan_data["id"],
                    scan_data.get("source_type", scan_data.get("target_type", "source_code")),
                    scan_data["target_name"],
                    scan_data["status"],
                    scan_data.get("language"),
                    summary_json,
                    scan_data.get("source_code"),
                    scan_data.get("created_at", datetime.now(timezone.utc).isoformat()),
                    scan_data.get("completed_at"),
                    scan_data.get("error_message"),
                    scan_data.get("lines_of_code", 0),
                    scan_data.get("duration_ms", 0.0),
                    scan_data.get("files_count", 1),
                    scan_data.get("vulnerability_density", 0.0),
                    scan_data.get("target_platform", "generic"),
                    scan_data.get("rtos"),
                    scan_data.get("compiler", "gcc"),
                    tool_json
                )
            )
    finally:
        conn.close()


def clear_all_scans(db_path: Optional[str] = None) -> None:
    """Wipe all scans, findings, remediations, and validations for a clean slate."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM validations")
            conn.execute("DELETE FROM remediations")
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM scans")
    finally:
        conn.close()


def get_scan(scan_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        data = dict(row)
        if "target_type" not in data or not data["target_type"]:
            data["target_type"] = data.get("source_type") or "code"
        if "source_type" not in data or not data["source_type"]:
            data["source_type"] = data.get("target_type") or "source_code"
        if data.get("summary"):
            try:
                data["summary"] = json.loads(data["summary"])
            except Exception:
                pass
        if data.get("tool_status"):
            try:
                data["tool_status"] = json.loads(data["tool_status"])
            except Exception:
                pass
        return data
    finally:
        conn.close()


def list_scans_paginated(
    limit: int = 20,
    offset: int = 0,
    db_path: Optional[str] = None
) -> tuple[List[Dict[str, Any]], int]:
    conn = get_db_connection(db_path)
    try:
        count_cursor = conn.execute("SELECT COUNT(*) as total FROM scans")
        total = count_cursor.fetchone()["total"]

        cursor = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        rows = cursor.fetchall()
        results = []
        for r in rows:
            item = dict(r)
            if "target_type" not in item or not item["target_type"]:
                item["target_type"] = item.get("source_type") or "code"
            if "source_type" not in item or not item["source_type"]:
                item["source_type"] = item.get("target_type") or "source_code"
            if item.get("summary"):
                try:
                    item["summary"] = json.loads(item["summary"])
                except Exception:
                    pass
            if item.get("tool_status"):
                try:
                    item["tool_status"] = json.loads(item["tool_status"])
                except Exception:
                    pass
            results.append(item)
        return results, total
    finally:
        conn.close()


def list_scans(limit: int = 50, offset: int = 0, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    items, _ = list_scans_paginated(limit=limit, offset=offset, db_path=db_path)
    return items


# Findings CRUD
def save_finding(finding_data: Dict[str, Any], db_path: Optional[str] = None) -> None:
    conn = get_db_connection(db_path)
    try:
        with conn:
            evidence_val = finding_data.get("evidence")
            evidence_json = json.dumps(evidence_val) if isinstance(evidence_val, dict) else evidence_val
            conn.execute(
                """
                INSERT INTO findings (
                    id, scan_id, title, severity, category, cwe_id, file_path,
                    line_start, line_end, evidence, description, impact,
                    recommendation, source, confidence, status, created_at,
                    cvss_score, cvss_version, rule_id, function_name, column_number,
                    root_cause, exploitation_conditions
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    description=excluded.description,
                    recommendation=excluded.recommendation,
                    status=excluded.status,
                    cvss_score=excluded.cvss_score,
                    cvss_version=excluded.cvss_version,
                    rule_id=excluded.rule_id,
                    function_name=excluded.function_name,
                    column_number=excluded.column_number,
                    root_cause=excluded.root_cause,
                    exploitation_conditions=excluded.exploitation_conditions
                """,
                (
                    finding_data["id"],
                    finding_data["scan_id"],
                    finding_data["title"],
                    finding_data["severity"].lower(),
                    finding_data.get("category", "Security"),
                    finding_data["cwe_id"],
                    finding_data["file_path"],
                    finding_data.get("line_start", finding_data.get("line_number")),
                    finding_data.get("line_end", finding_data.get("line_number")),
                    evidence_json,
                    finding_data.get("description", finding_data.get("title", "Security finding")),
                    finding_data.get("impact"),
                    finding_data.get("recommendation"),
                    finding_data.get("source", "ast_scanner"),
                    finding_data.get("confidence", "high"),
                    finding_data.get("status", "open"),
                    finding_data.get("created_at", datetime.now(timezone.utc).isoformat()),
                    finding_data.get("cvss_score"),
                    finding_data.get("cvss_version", "3.1"),
                    finding_data.get("rule_id"),
                    finding_data.get("function_name"),
                    finding_data.get("column_number", 1),
                    finding_data.get("root_cause"),
                    finding_data.get("exploitation_conditions")
                )
            )
    finally:
        conn.close()


# Firmware Syntheses CRUD
def save_firmware_synthesis(synth_data: Dict[str, Any], db_path: Optional[str] = None) -> None:
    conn = get_db_connection(db_path)
    try:
        with conn:
            deps_json = json.dumps(synth_data.get("dependencies", []))
            secs_json = json.dumps(synth_data.get("security_considerations", []))
            conn.execute(
                """
                INSERT INTO firmware_syntheses (
                    id, requirement, target_platform, rtos, component_type, title,
                    source_code, header_code, configuration_file, dependencies,
                    security_considerations, unit_tests, explanation, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    source_code=excluded.source_code,
                    header_code=excluded.header_code,
                    explanation=excluded.explanation
                """,
                (
                    synth_data["id"],
                    synth_data["requirement"],
                    synth_data.get("target_platform", "generic_embedded"),
                    synth_data.get("rtos"),
                    synth_data.get("component_type", "custom"),
                    synth_data.get("title", "Synthesized Firmware Component"),
                    synth_data.get("source_code", ""),
                    synth_data.get("header_code", ""),
                    synth_data.get("configuration_file"),
                    deps_json,
                    secs_json,
                    synth_data.get("unit_tests", ""),
                    synth_data.get("explanation", ""),
                    synth_data.get("created_at", datetime.now(timezone.utc).isoformat())
                )
            )
    finally:
        conn.close()


def list_firmware_syntheses(limit: int = 20, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT * FROM firmware_syntheses ORDER BY created_at DESC LIMIT ?",
            (limit,)
        )
        rows = cursor.fetchall()
        results = []
        for r in rows:
            item = dict(r)
            if item.get("dependencies"):
                try:
                    item["dependencies"] = json.loads(item["dependencies"])
                except Exception:
                    pass
            if item.get("security_considerations"):
                try:
                    item["security_considerations"] = json.loads(item["security_considerations"])
                except Exception:
                    pass
            results.append(item)
        return results
    finally:
        conn.close()


def get_findings_by_scan_id(scan_id: str, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY line_start ASC", (scan_id,))
        results = []
        for r in cursor.fetchall():
            item = dict(r)
            if item.get("evidence"):
                try:
                    item["evidence"] = json.loads(item["evidence"])
                except Exception:
                    pass
            results.append(item)
        return results
    finally:
        conn.close()


def get_finding(finding_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = cursor.fetchone()
        if not row:
            return None
        item = dict(row)
        if item.get("evidence"):
            try:
                item["evidence"] = json.loads(item["evidence"])
            except Exception:
                pass
        return item
    finally:
        conn.close()


# Remediations CRUD
def save_remediation(remediation_data: Dict[str, Any], db_path: Optional[str] = None) -> None:
    conn = get_db_connection(db_path)
    try:
        limitations_val = remediation_data.get("limitations")
        limitations_json = json.dumps(limitations_val) if isinstance(limitations_val, list) else limitations_val

        with conn:
            conn.execute(
                """
                INSERT INTO remediations (
                    id, scan_id, finding_id, status, original_code, patched_code,
                    unified_diff, explanation, created_at, updated_at, error_message,
                    original_hash, proposed_hash, provider, model, patch_summary,
                    limitations, validation_status, artifact_path, requires_review,
                    added_lines, removed_lines
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    patched_code=excluded.patched_code,
                    unified_diff=excluded.unified_diff,
                    explanation=excluded.explanation,
                    updated_at=excluded.updated_at,
                    error_message=excluded.error_message,
                    original_hash=excluded.original_hash,
                    proposed_hash=excluded.proposed_hash,
                    provider=excluded.provider,
                    model=excluded.model,
                    patch_summary=excluded.patch_summary,
                    limitations=excluded.limitations,
                    validation_status=excluded.validation_status,
                    artifact_path=excluded.artifact_path,
                    requires_review=excluded.requires_review,
                    added_lines=excluded.added_lines,
                    removed_lines=excluded.removed_lines
                """,
                (
                    remediation_data["id"],
                    remediation_data["scan_id"],
                    remediation_data["finding_id"],
                    remediation_data.get("status", "completed"),
                    remediation_data["original_code"],
                    remediation_data["patched_code"],
                    remediation_data["unified_diff"],
                    remediation_data.get("explanation"),
                    remediation_data.get("created_at", datetime.now(timezone.utc).isoformat()),
                    remediation_data.get("updated_at", datetime.now(timezone.utc).isoformat()),
                    remediation_data.get("error_message"),
                    remediation_data.get("original_hash"),
                    remediation_data.get("proposed_hash"),
                    remediation_data.get("provider", "gemini"),
                    remediation_data.get("model"),
                    remediation_data.get("patch_summary") or remediation_data.get("summary"),
                    limitations_json,
                    remediation_data.get("validation_status", "UNVALIDATED"),
                    remediation_data.get("artifact_path"),
                    1 if remediation_data.get("requires_review", True) else 0,
                    remediation_data.get("added_lines", 0),
                    remediation_data.get("removed_lines", 0)
                )
            )
    finally:
        conn.close()


def get_remediation(remediation_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM remediations WHERE id = ?", (remediation_id,))
        row = cursor.fetchone()
        if not row:
            return None
        item = dict(row)
        if item.get("limitations"):
            try:
                item["limitations"] = json.loads(item["limitations"])
            except Exception:
                pass
        item["requires_review"] = bool(item.get("requires_review", 1))
        return item
    finally:
        conn.close()


def get_remediations_by_finding_id(finding_id: str, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM remediations WHERE finding_id = ? ORDER BY created_at DESC", (finding_id,))
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


# Validations CRUD
def save_validation(validation_data: Dict[str, Any], db_path: Optional[str] = None) -> None:
    conn = get_db_connection(db_path)
    try:
        with conn:
            new_findings_val = validation_data.get("new_findings")
            new_findings_json = json.dumps(new_findings_val) if isinstance(new_findings_val, (list, dict)) else new_findings_val

            checks_val = validation_data.get("checks")
            checks_json = json.dumps(checks_val) if isinstance(checks_val, list) else checks_val

            summary_str = validation_data.get("summary") or validation_data.get("message", "")

            conn.execute(
                """
                INSERT INTO validations (
                    id, remediation_id, status, is_valid, syntax_valid,
                    target_vulnerability_eradicated, new_findings_count,
                    new_findings, message, created_at, completed_at,
                    checks, findings_before, findings_after, summary, requires_human_review
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    is_valid=excluded.is_valid,
                    syntax_valid=excluded.syntax_valid,
                    target_vulnerability_eradicated=excluded.target_vulnerability_eradicated,
                    new_findings_count=excluded.new_findings_count,
                    new_findings=excluded.new_findings,
                    message=excluded.message,
                    completed_at=excluded.completed_at,
                    checks=excluded.checks,
                    findings_before=excluded.findings_before,
                    findings_after=excluded.findings_after,
                    summary=excluded.summary,
                    requires_human_review=excluded.requires_human_review
                """,
                (
                    validation_data["id"],
                    validation_data["remediation_id"],
                    validation_data.get("status", "completed"),
                    1 if validation_data.get("is_valid") else 0,
                    1 if validation_data.get("syntax_valid") else 0,
                    1 if validation_data.get("target_vulnerability_eradicated") else 0,
                    validation_data.get("new_findings_count", 0),
                    new_findings_json,
                    summary_str,
                    validation_data.get("created_at", datetime.now(timezone.utc).isoformat()),
                    validation_data.get("completed_at"),
                    checks_json,
                    validation_data.get("findings_before", 0),
                    validation_data.get("findings_after", 0),
                    summary_str,
                    1 if validation_data.get("requires_human_review", True) else 0
                )
            )
    finally:
        conn.close()


def get_validation(validation_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM validations WHERE id = ?", (validation_id,))
        row = cursor.fetchone()
        if not row:
            return None
        data = dict(row)
        data["is_valid"] = bool(data["is_valid"])
        data["syntax_valid"] = bool(data["syntax_valid"])
        data["target_vulnerability_eradicated"] = bool(data["target_vulnerability_eradicated"])
        data["requires_human_review"] = bool(data.get("requires_human_review", 1))
        if data.get("new_findings"):
            try:
                data["new_findings"] = json.loads(data["new_findings"])
            except Exception:
                pass
        if data.get("checks"):
            try:
                data["checks"] = json.loads(data["checks"])
            except Exception:
                pass
        else:
            data["checks"] = []
        if not data.get("summary") and data.get("message"):
            data["summary"] = data["message"]
        return data
    finally:
        conn.close()
