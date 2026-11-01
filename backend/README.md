# VULNEX AI — Backend & REST API Specification

> AI-Assisted Vulnerability Detection and Secure Code Repair Platform.

This document specifies the stable REST API contract for the React frontend and client integrations.

---

## 1. Quickstart & Server Execution

```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

- **Interactive Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Interactive ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **API Base URL**: `http://localhost:8000/api/v1`

---

## 2. Environment & CORS Configuration

Configure `.env` using `.env.example` as a template:

```env
VULNEX_ENV=development
VULNEX_PORT=8000
VULNEX_HOST=0.0.0.0

# CORS Configuration for React Frontend
FRONTEND_ORIGIN=http://localhost:3000,http://localhost:5173

# AI Provider Configuration
AI_PROVIDER=gemini
AI_MODEL=gemini-1.5-pro
AI_API_KEY=
GEMINI_API_KEY=
GEMINI_MODEL=gemini-1.5-pro

# AI Reliability Limits
AI_TIMEOUT_SECONDS=15
AI_MAX_RETRIES=2

# Security Limits
MAX_SCAN_FILE_SIZE_BYTES=2097152
MAX_REPO_CLONE_SIZE_BYTES=20971520
REPO_CLONE_TIMEOUT_SECONDS=30
DATABASE_PATH=vulnex.db
```

---

## 3. Standard Data Types & Error Model

### Severity Values
`critical` | `high` | `medium` | `low` | `info` | `unknown`

### Scan Lifecycle States
`queued` | `running` | `completed` | `failed` | `cancelled`

### Remediation & Validation Lifecycle States
`queued` | `running` | `completed` | `failed` | `requires_review`

### Standard Error Response Format
All HTTP errors return consistent JSON with request correlation:
```json
{
  "error_code": "NOT_FOUND",
  "message": "Finding with ID 'find_123' not found.",
  "request_id": "req_80c85eb0ab"
}
```

---

## 4. Endpoints & API Contract

### 1. `GET /api/v1/health`
Returns system status, version, and AI provider status (distinguishing configured vs tested and available).

**Response (200 OK):**
```json
{
  "status": "ok",
  "service": "vulnex-api",
  "version": "1.0.0",
  "ai_provider": {
    "provider": "gemini",
    "configured": false,
    "tested": false,
    "available": false,
    "model": "gemini-1.5-pro",
    "message": "AI provider API key is not configured"
  }
}
```

---

### 2. `POST /api/v1/scans`
Initiates static analysis of source code or an authorized repository. Does not accept arbitrary filesystem paths.

**Request (Source Code):**
```json
{
  "source_type": "source_code",
  "language": "python",
  "filename": "database_service.py",
  "source_code": "import sqlite3\ndef query(uid):\n    cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
}
```

**Request (Repository):**
```json
{
  "source_type": "repository",
  "repo_url": "https://github.com/my-org/auth-service.git",
  "branch": "main",
  "auth_token": "ghp_optional_token"
}
```

**Response (201 Created):**
```json
{
  "id": "scan_a1f9e018d9bc",
  "source_type": "source_code",
  "target_name": "database_service.py",
  "status": "completed",
  "language": "python",
  "summary": {
    "total": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "unknown": 0
  },
  "created_at": "2026-11-01T02:00:00Z",
  "completed_at": "2026-11-01T02:00:01Z",
  "error_message": null
}
```

---

### 3. `GET /api/v1/scans/{scan_id}`
Returns current scan state and summary.

**Response (200 OK):**
```json
{
  "id": "scan_a1f9e018d9bc",
  "source_type": "source_code",
  "target_name": "database_service.py",
  "status": "completed",
  "language": "python",
  "summary": {
    "total": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "unknown": 0
  },
  "created_at": "2026-11-01T02:00:00Z",
  "completed_at": "2026-11-01T02:00:01Z",
  "error_message": null
}
```

---

### 4. `GET /api/v1/scans/{scan_id}/findings`
Returns normalized findings associated with a scan.

**Response (200 OK):**
```json
[
  {
    "id": "find_3f94e18c50ba",
    "scan_id": "scan_a1f9e018d9bc",
    "title": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
    "severity": "critical",
    "category": "SQL Injection",
    "cwe_id": "CWE-89",
    "file_path": "database_service.py",
    "line_start": 3,
    "line_end": 3,
    "evidence": {
      "snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')",
      "context": null,
      "ast_rule": "VULN-SQLI-001",
      "pattern": "VULN-SQLI-001"
    },
    "description": "SQL query constructed via dynamic string interpolation directly inside cursor.execute.",
    "impact": "Unauthorized database read/write, privilege escalation, authentication bypass.",
    "recommendation": "Use parameterized queries with database placeholders.",
    "source": "ast_scanner",
    "confidence": "high",
    "status": "open"
  }
]
```

---

### 5. `GET /api/v1/findings/{finding_id}`
Returns a detailed finding, including its evidence and source location.

**Response (200 OK):**
```json
{
  "id": "find_3f94e18c50ba",
  "scan_id": "scan_a1f9e018d9bc",
  "title": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
  "severity": "critical",
  "category": "SQL Injection",
  "cwe_id": "CWE-89",
  "file_path": "database_service.py",
  "line_start": 3,
  "line_end": 3,
  "evidence": {
    "snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')",
    "context": null,
    "ast_rule": "VULN-SQLI-001",
    "pattern": "VULN-SQLI-001"
  },
  "description": "SQL query constructed via dynamic string interpolation directly inside cursor.execute.",
  "impact": "Unauthorized database read/write, privilege escalation, authentication bypass.",
  "recommendation": "Use parameterized queries with database placeholders.",
  "source": "ast_scanner",
  "confidence": "high",
  "status": "open"
}
```

---

### 6. `POST /api/v1/findings/{finding_id}/remediations`
Create a remediation request for a specific finding.
Executes the strict 10-step remediation workflow:
1. Loads selected finding.
2. Loads corresponding original source without overwriting.
3. Confirms finding belongs to source code.
4. Retrieves relevant source excerpt and scanner evidence.
5. Obtains AI-generated patch proposal (with deterministic fallback).
6. Validates proposal schema (`AIPatchProposal`).
7. Checks non-empty proposed code, flags unchanged output, and detects code drift.
8. Calculates unified diff with explicit newline normalization (CRLF/LF).
9. Stores patch as separate segregated artifacts on disk (`artifacts/patches/{id}/`).
10. Returns proposed patch with lifecycle state and `UNVALIDATED` validation status.

**Request:**
```json
{
  "prompt_context": "Parameterize query using %s placeholders",
  "auto_validate": false
}
```

**Response (201 Created):**
```json
{
  "id": "rem_5e921d8b20cc",
  "finding_id": "find_3f94e18c50ba",
  "scan_id": "scan_a1f9e018d9bc",
  "status": "completed",
  "summary": "Replaced dynamic SQL f-string interpolation with parameterized query execution.",
  "explanation": "Dynamic query was replaced by cursor.execute(query, params) to eradicate SQL injection.",
  "limitations": [],
  "original_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "proposed_hash": "d2a019b87b7a24c7f070e3ae4d62283a0ad3a943a41b528148b3c3b0dfb7201c",
  "provider": "gemini",
  "model": "gemini-1.5-pro",
  "validation_status": "UNVALIDATED",
  "requires_review": true,
  "artifact_path": "artifacts/patches/rem_5e921d8b20cc",
  "added_lines": 1,
  "removed_lines": 1,
  "created_at": "2026-11-01T02:00:05Z",
  "updated_at": "2026-11-01T02:00:05Z",
  "error_message": null
}
```

---

### 7. `GET /api/v1/remediations/{remediation_id}`
Return the remediation status and available result metadata.

**Response (200 OK):**
```json
{
  "id": "rem_5e921d8b20cc",
  "finding_id": "find_3f94e18c50ba",
  "scan_id": "scan_a1f9e018d9bc",
  "status": "completed",
  "summary": "Replaced dynamic SQL f-string interpolation with parameterized query execution.",
  "explanation": "Replaced dynamic SQL f-string interpolation with parameterized query execution.",
  "limitations": [],
  "original_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "proposed_hash": "d2a019b87b7a24c7f070e3ae4d62283a0ad3a943a41b528148b3c3b0dfb7201c",
  "provider": "gemini",
  "model": "gemini-1.5-pro",
  "validation_status": "UNVALIDATED",
  "requires_review": true,
  "artifact_path": "artifacts/patches/rem_5e921d8b20cc",
  "added_lines": 1,
  "removed_lines": 1,
  "created_at": "2026-11-01T02:00:05Z",
  "updated_at": "2026-11-01T02:00:05Z",
  "error_message": null
}
```

---

### 8. `GET /api/v1/remediations/{remediation_id}/diff`
Return the original and proposed code and unified diff.

**Response (200 OK):**
```json
{
  "remediation_id": "rem_5e921d8b20cc",
  "finding_id": "find_3f94e18c50ba",
  "file_path": "database_service.py",
  "original_code": "import sqlite3\ndef query(uid):\n    cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n",
  "proposed_code": "import sqlite3\ndef query(uid):\n    cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n",
  "unified_diff": "--- a/database_service.py\n+++ b/database_service.py\n@@ -1,3 +1,3 @@\n import sqlite3\n def query(uid):\n-    cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n+    cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n",
  "changes_count": 2,
  "added_lines": 1,
  "removed_lines": 1,
  "original_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "proposed_hash": "d2a019b87b7a24c7f070e3ae4d62283a0ad3a943a41b528148b3c3b0dfb7201c",
  "summary": "Replaced dynamic SQL f-string interpolation with parameterized query execution.",
  "explanation": "Dynamic query was replaced by cursor.execute(query, params) to eradicate SQL injection.",
  "limitations": [],
  "validation_status": "UNVALIDATED",
  "requires_review": true
}
```

---

### 9. `POST /api/v1/remediations/{remediation_id}/validate`
Request isolated verification and regression re-scanning of the proposed patch.
Executes the 10-step secure validation pipeline:
1. Confirms patch artifact existence.
2. Compares original vs proposed source hashes.
3. Applies patch in an isolated temporary workspace.
4. Executes static AST syntax validation (zero host execution).
5. Executes trusted tests strictly in an isolated container sandbox (never on host bare metal; returns `not_available` / `validation_unavailable` if container sandbox is not available).
6. Re-scans patched code with Bandit, Semgrep, and native AST scanner.
7. Evaluates flaw eradication (dual scanner + structural check) and zero regressions.
8. Records actual check outputs, durations, and exit codes.
9. Synthesizes validation summary with `requires_human_review=true`.
10. Automatically destroys temporary workspace.

**Request:**
```json
{
  "strict_mode": true,
  "trusted_test_command": "pytest -v tests/"
}
```

**Response (201 Created):**
```json
{
  "id": "val_1a98c0b240ff",
  "validation_id": "val_1a98c0b240ff",
  "remediation_id": "rem_5e921d8b20cc",
  "status": "completed",
  "is_valid": true,
  "syntax_valid": true,
  "target_vulnerability_eradicated": true,
  "checks": [
    {
      "name": "hash_comparison",
      "status": "passed",
      "details": "Verified patch modified source: orig=e3b0c44298fc..., prop=d2a019b87b7a...",
      "exit_code": null,
      "duration_ms": null
    },
    {
      "name": "syntax_check",
      "status": "passed",
      "details": "Code parsed successfully with zero syntax errors via static AST parser.",
      "exit_code": null,
      "duration_ms": 1.2
    },
    {
      "name": "unit_tests",
      "status": "not_available",
      "details": "No trusted test suite was configured for this remediation.",
      "exit_code": null,
      "duration_ms": null
    },
    {
      "name": "static_security_rescan",
      "status": "passed",
      "details": "Re-scan passed: 0 regressions introduced. Baseline: 1, Post-patch: 0.",
      "exit_code": 0,
      "duration_ms": 35.4
    }
  ],
  "findings_before": 1,
  "findings_after": 0,
  "new_findings_count": 0,
  "new_findings": [],
  "summary": "Validation completed: Patch compiles cleanly, resolves target vulnerability, and introduces no regressions.",
  "message": "Validation completed: Patch compiles cleanly, resolves target vulnerability, and introduces no regressions.",
  "requires_human_review": true,
  "created_at": "2026-11-01T02:00:10Z",
  "completed_at": "2026-11-01T02:00:10Z"
}
```

---

### 10. `GET /api/v1/validations/{validation_id}`
Return validation progress, itemized check results, and actual regression check results.

**Response (200 OK):**
```json
{
  "id": "val_1a98c0b240ff",
  "validation_id": "val_1a98c0b240ff",
  "remediation_id": "rem_5e921d8b20cc",
  "status": "completed",
  "is_valid": true,
  "syntax_valid": true,
  "target_vulnerability_eradicated": true,
  "checks": [
    {
      "name": "hash_comparison",
      "status": "passed",
      "details": "Verified patch modified source: orig=e3b0c44298fc..., prop=d2a019b87b7a..."
    },
    {
      "name": "syntax_check",
      "status": "passed",
      "details": "Code parsed successfully with zero syntax errors via static AST parser."
    },
    {
      "name": "unit_tests",
      "status": "not_available",
      "details": "No trusted test suite was configured for this remediation."
    },
    {
      "name": "static_security_rescan",
      "status": "passed",
      "details": "Re-scan passed: 0 regressions introduced. Baseline: 1, Post-patch: 0."
    }
  ],
  "findings_before": 1,
  "findings_after": 0,
  "new_findings_count": 0,
  "new_findings": [],
  "summary": "Validation completed: Patch compiles cleanly, resolves target vulnerability, and introduces no regressions.",
  "message": "Validation completed: Patch compiles cleanly, resolves target vulnerability, and introduces no regressions.",
  "requires_human_review": true,
  "created_at": "2026-11-01T02:00:10Z",
  "completed_at": "2026-11-01T02:00:10Z"
}
```

---

### 11. `GET /api/v1/scans`
Return paginated scan history.

**Query Parameters:**
- `page`: int (default `1`, min `1`)
- `limit`: int (default `20`, min `1`, max `100`)

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "scan_a1f9e018d9bc",
      "source_type": "source_code",
      "target_name": "database_service.py",
      "status": "completed",
      "language": "python",
      "summary": {
        "total": 1,
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0
      },
      "created_at": "2026-11-01T02:00:00Z",
      "completed_at": "2026-11-01T02:00:01Z",
      "error_message": null
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 20,
  "pages": 1
}
```

---

## 5. Running Automated Contract Tests

Execute the 69 automated tests:

```bash
python -m pytest -v
```

---

## 6. Static Security Scanning Service

### Overview & Security Scope
The static security scanning service supports Python source code security audits through integrated **Bandit** and **Semgrep** engines alongside safe native AST visitors. Scanner execution is completely separated from API routing and AI synthesis.

> [!IMPORTANT]
> **Exploitability Disclaimer**: Static security scanning detects code patterns, API misuse, and architectural antipatterns associated with known vulnerability classes. The presence of a finding indicates a potential security risk and a violation of defensive guidelines; it does not constitute mathematical proof of practical exploitability in every deployment scenario, nor does the absence of findings prove the complete absence of all vulnerabilities.

### 11-Step Scanning Pipeline
1. **Validate Language**: Ensures source code matches configured language engines (`python`).
2. **Validate Filename**: Strips directory traversal sequences (`../`, `\`, `/`) to prevent filesystem manipulation.
3. **Enforce Size Limits**: Enforces `MAX_SCAN_FILE_SIZE_BYTES` (default 2MB) and rejects empty payloads.
4. **Controlled Temporary Workspace**: Isolates submitted source in an ephemeral directory with strict cleanup upon completion.
5. **Non-Executing Invocation**: Invokes `bandit` and `semgrep` as external static inspection CLI processes without executing or evaluating the code.
6. **Execution Timeouts**: Enforces process timeouts (default 15–20s) to guard against denial-of-service.
7. **Safe Output Capture**: Captures subprocess streams with explicit UTF-8 decoding and error-replacement to handle platform-specific encodings.
8. **JSON Result Parsing**: Parses machine-readable outputs into structured scanner results.
9. **Normalization**: Normalizes results into the standard API `Finding` schema, preserving original scanner names and rule IDs.
10. **Storage**: Persists the scan record, severity metrics, and individual findings in SQLite.
11. **Response**: Emits structured scan summary and findings to the caller.

### Configured Rule Sets

#### Bandit Rule Sets (OpenSSF Bandit)
- `B608`: Hardcoded SQL expressions / SQL Injection (CWE-89)
- `B605` / `B602`: Process started with a shell / Shell Injection (CWE-78)
- `B301`: Insecure deserialization via `pickle.loads` / `pickle.load` (CWE-502)
- `B324` / `B303`: Use of weak cryptographic hash (MD5, SHA1) (CWE-327)
- `B102` / `B307`: Dynamic code evaluation via `eval` / `exec` (CWE-95)
- `B105` / `B106` / `B107`: Hardcoded passwords and secret tokens (CWE-798)

*(Note: Blacklist import warnings `B404` and `B603` for safe `subprocess.run(..., shell=False)` are excluded to prevent false positives on secure remediation code.)*

#### Semgrep Rule Sets (`semgrep_python_security.yaml`)
- `python.security.injection.sql.formatted-query`: Formatted SQL execution in cursor queries (CWE-89)
- `python.security.injection.command.os-system`: Direct shell execution via `os.system` (CWE-78)
- `python.security.injection.command.subprocess-shell`: Subprocess execution with `shell=True` (CWE-78)
- `python.security.deserialization.pickle`: Arbitrary object deserialization via `pickle` (CWE-502)
- `python.security.deserialization.yaml-unsafe`: YAML deserialization with unsafe loaders (CWE-502)
- `python.security.crypto.weak-hash`: Cryptographic hashing using MD5 or SHA-1 (CWE-327)
- `python.security.dynamic-code.eval-exec`: Dynamic code evaluation via `eval` or `exec` (CWE-95)

### Evidence & Secret Redaction
Evidence snippets extracted from target files are bounded to the relevant lines and redacted:
- API keys, JWT secrets, passwords, and tokens are replaced with `[REDACTED_SECRET]` or `[REDACTED_GEMINI_KEY]`.
- Private keys (`-----BEGIN PRIVATE KEY-----`) are automatically masked.

### Safe Test Fixtures
Test fixtures in `fixtures/` provide paired vulnerable vs remediated examples:
- `sql_injection_pattern.py` vs `sql_injection_secure.py`
- `command_injection_pattern.py` vs `command_injection_secure.py`
- `insecure_deserialization_pattern.py` vs `insecure_deserialization_secure.py`
- `secret_leak_pattern.py` vs `secret_leak_secure.py`
- `vulnerable_app.py` vs `clean_app.py`

---

## 7. AI Service: Finding Analysis & Secure Patch Generation

### Overview & Security Model
The AI service (`app/services/ai_service.py`) generates deep plain-language explanations of scanner findings and synthesizes proposed secure code repairs. The AI service **never replaces** the static security scanner as the source of truth for findings; findings originate objectively from the static analyzers.

### Environment Configuration
The service supports the following environment variables:
- `AI_PROVIDER`: Selected provider (`gemini` default).
- `AI_MODEL`: Model identifier (e.g. `gemini-1.5-pro` or `gemini-1.5-flash`).
- `AI_API_KEY`: Provider API key.
- `GEMINI_API_KEY`: Alias for Google Gemini API key.
- `AI_TIMEOUT_SECONDS`: Request timeout (default 15s).
- `AI_MAX_RETRIES`: Maximum exponential backoff retries on transient errors (default 2).

> [!CAUTION]
> **Credential Protection**: API keys are never printed in logs, never included in error messages, and never returned to the frontend. If unconfigured, the service returns an explicit `UNCONFIGURED` state without crashing or leaking stack traces.

### AI Finding Analysis Contract (`AIFindingAnalysis`)
Analyzes a scanner finding with relevant source excerpts and outputs:
- `explanation`: Plain-language breakdown of the vulnerability.
- `potential_impact`: Real-world security risks if exploited.
- `flagged_reason`: Why the static scanner flagged this pattern.
- `recommended_remediation`: Concrete remediation strategy.
- `secure_coding_guidance`: List of architectural principles.
- `uncertainties_and_assumptions`: Explicit contextual assumptions.
- `scanner_evidence_distinction`: Explicit demarcation distinguishing objective scanner evidence from AI interpretation.

### AI Patch Generation Contract (`AIPatchProposal`)
Synthesizes a proposed repair as strict validated JSON:
```json
{
  "summary": "Parameterize SQL execution",
  "rationale": "Replaces dynamic f-string with %s placeholders to prevent SQL injection.",
  "patched_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
  "changes": [
    {
      "description": "Converted string format to parameterized argument",
      "lines_affected": "line 16"
    }
  ],
  "limitations": [
    "Requires database driver supporting %s placeholder formatting."
  ]
}
```

### Untrusted Proposal & Validation Policy
- AI-generated patches are **untrusted proposals**. The system sets `requires_review: true` and `validation_state: "UNVALIDATED"` by default.
- No patch is marked as verified merely because the model generated it. Validation only transitions to `VALIDATED` after the isolated `ValidationService` re-scans the code and confirms the vulnerability is eradicated with zero regressions.

### Prompt-Injection Defense
- All submitted source code, comments, filenames, and scanner texts are wrapped in strict `<untrusted_source_code>` fences.
- The system instructions mandate that the model must ignore any embedded instructions attempting to modify security policy, reveal credentials, execute arbitrary commands, access local files, or claim tests passed.

---

## 8. Secure Validation Service & Sandbox Architecture

### Threat Model & Defense Invariants
Submitted code and generated patches are treated as untrusted and potentially malicious:
1. **Zero Host Execution**: The API server never executes submitted source code directly on the host machine.
2. **Never Fall Back to Unsafe Execution**: If an isolated container sandbox is unavailable in the environment, the service refuses to run dynamic tests on the host and records `validation_unavailable` or `requires_review`.
3. **Subprocess Timeouts are Insufficient**: A timeout alone does not make arbitrary code execution safe. Dynamic execution requires non-root containment, disabled network, process limits, and memory limits.

### Sandbox Architecture Requirements
When container execution is enabled, the sandbox enforces:
- **Non-Root Execution**: Runs as non-root user (`--user 1000:1000`).
- **Network Isolation**: Strict `--network=none` blocking inbound/outbound requests and loopback access.
- **Resource Constraints**:
  - Memory: `--memory=256m`
  - CPU: `--cpus=0.5`
  - Process limit: `--pids-limit=50`
- **Read-Only Root Filesystem**: `--read-only` rootfs prevents system tampering.
- **Segregated Ephemeral Workspace**: Only the temporary job workspace is mounted; destroyed automatically upon completion.
- **Environment Sanitization**: No host secrets, API keys, or cloud credentials are passed into the sandbox.

### 10-Step Validation Pipeline Checks
Every validation job executes itemized checks:
1. **Artifact Verification**: Confirms remediation record and patch artifacts exist.
2. **Hash Comparison**: Verifies original vs proposed SHA-256 hashes.
3. **Workspace Isolation**: Allocates a temporary segregated directory (`tempfile.TemporaryDirectory`).
4. **Syntax Check**: Performs non-executing AST compilation (`check_syntax_safely`). Never calls `eval` or `exec`.
5. **Trusted Dynamic Tests**: Runs configured tests inside the container sandbox only if container runtime is verified. If absent, marks `not_available` with explicit refusal reason.
6. **Static Security Re-Scan**: Re-scans patched code using Bandit, Semgrep, and AST visitors without execution.
7. **Flaw Eradication & Structural Check**: Dual verification ensuring the target vulnerability is eradicated structurally and by scanner without blindspots.
8. **Regression Analysis**: Confirms zero new security findings are introduced.
9. **Summary Synthesis**: Compiles itemized check outcomes into structured JSON (`checks`, `findings_before`, `findings_after`, `summary`, `requires_human_review`).
10. **Workspace Cleanup**: Automatically wipes and removes the temporary directory in a `finally` block.

