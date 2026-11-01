# VULNEX AI

**AI-Assisted Vulnerability Detection & Verified Code Repair Platform**

VULNEX AI analyzes source code, uploaded files, and remote repositories for security vulnerabilities, generates AI-powered threat explanations, synthesizes secure patches as unified diffs, and validates every repair in an isolated syntax and regression sandbox before presenting it to the user.

---

## Architecture & Layout

```
vulnex-ai/
  backend/               # FastAPI REST Backend (/api/v1)
    app/
      api/               # REST Route Handlers (health, scans, findings, remediations, validations)
      config.py          # Pydantic Settings & CORS configuration
      models/            # Database schema & Pydantic domain models
      security/          # Host-safe isolated execution sandbox & AST taint checkers
      services/          # Static scanning (Bandit/Semgrep), AI engine (Gemini), Patch & Validation
      storage/           # SQLite persistent database & artifact file storage
    tests/               # 71 Automated pytest tests covering all security workflows
    pytest.ini           # Pytest isolation configuration
    requirements.txt     # Backend dependencies
    .env.example         # Backend environment template (AI keys & server settings)
  frontend/              # React 19 + TypeScript + Vite Frontend (AI Studio UI)
    src/
      components/        # Overview, NewScan, Vulnerabilities, RemediationWorkbench, ValidationLab, ScanHistory, Settings
      context/           # VulnexContext (Live API state management vs Demo data)
      services/          # apiClient (Typed REST client, HTTP error classification, data adapters)
      data/              # Seed fixtures & TypeScript data models
    .env.example         # Frontend configuration template (VITE_API_BASE_URL)
  examples/              # Safe demonstration fixtures with synthetic tokens
    sql_injection_vulnerable.py          # CWE-89 vulnerable pattern
    sql_injection_secure.py              # CWE-89 secure parameterized counterpart
    hardcoded_credential_vulnerable.py   # CWE-798 vulnerable synthetic secret
    hardcoded_credential_secure.py       # CWE-798 secure environment lookup counterpart
    README.md                            # Fixture documentation & CWE mappings
  fixtures/              # Vulnerable & remediated application test fixtures
    vulnerable_app.py    # Demonstrates CWE-89, CWE-78, CWE-502, CWE-327, CWE-798
    clean_app.py         # Remediated secure baseline
```

---

## Getting Started

### 1. Prerequisites
- Python 3.10+ (with `venv` support)
- Node.js 18+ & npm

### 2. Configure & Run Backend

```bash
cd backend

# Create & activate virtual environment (if not already done)
python -m venv venv
venv\Scripts\activate  # On Windows: venv\Scripts\activate; On Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment (Optional: AI keys for live Gemini patch generation)
cp .env.example .env
# Edit .env to set GEMINI_API_KEY if desired

# Start FastAPI server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

- **Interactive API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check & AI Probe**: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

### 3. Configure & Run Frontend

```bash
cd frontend

# Install dependencies
npm install --legacy-peer-deps

# Configure API Base URL
cp .env.example .env
# Default: VITE_API_BASE_URL=http://localhost:8000/api/v1

# Start Vite development server
npm run dev
```

- **Application UI**: [http://localhost:5173](http://localhost:5173)

---

## Live Hackathon Demonstration Guide (3–5 Minute Pitch)

### Required Environment Variables

#### Backend (`backend/.env`):
| Variable | Required | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `AI_PROVIDER` | No | `gemini` | Configured AI provider (`gemini`) |
| `GEMINI_API_KEY` | Optional | `""` | Gemini API token for live LLM synthesis (if omitted, falls back to deterministic AST patch synthesis) |
| `GEMINI_MODEL` | No | `gemini-1.5-pro` | Gemini model identifier |
| `VULNEX_PORT` | No | `8000` | Backend listening port |
| `CORS_ORIGINS` | No | `http://localhost:5173,...` | Allowed CORS origins for the frontend |

#### Frontend (`frontend/.env`):
| Variable | Required | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `VITE_API_BASE_URL` | Yes | `http://localhost:8000/api/v1` | Root URL for the FastAPI backend |

> [!CAUTION]
> Backend secrets (`GEMINI_API_KEY`, etc.) must **never** be placed in frontend `.env` files. The frontend only communicates with the backend via REST endpoints.

---

### Step-by-Step Demonstration Script

```
[00:00 - 00:30] Introduction & Platform Connectivity
  1. Open http://localhost:5173 in the browser.
  2. Point out TopNav status: "API v1 Connected" (🟢 LIVE API mode).
  3. Show the "Reset Demo" button that resets all scan sessions to a clean state.

[00:30 - 01:30] Source Code Static Scanning
  4. Navigate to "New Scan" tab.
  5. Click the "Python SQLi (CWE-89)" preset button.
     - Notice the vulnerable snippet from examples/sql_injection_vulnerable.py is loaded.
  6. Click "Start Security Scan".
  7. Watch real-time terminal telemetry logs as the backend invokes Bandit and AST taint analysis without executing untrusted code.

[01:30 - 02:30] Finding Exploration & AI Explanation
  8. Click "Inspect Findings" or navigate to "Vulnerability Findings".
  9. Click on the detected CWE-89 finding to open the Inspector drawer:
     - Review the exact vulnerable line (cursor.execute).
     - Inspect the scanner rule ID (VULN-SQLI-001 / Bandit B608).
     - Read the AI-generated impact analysis explaining SQL injection risks.

[02:30 - 03:30] Secure Patch Generation & Unified Diff
  10. Click "Fix" to enter the AI Remediation Workbench.
  11. Click "Generate Patch":
      - VULNEX AI synthesizes the parameterized query replacement.
  12. Toggle between "Split View" and "Unified Diff View":
      - Inspect the unified diff: shows removed string interpolation (-) and added parameter tuple (+).

[03:30 - 04:30] Host-Safe Validation Sandbox
  13. Click "Validate Patch":
      - Backend executes the isolated validation pipeline inside an ephemeral non-root sandbox.
      - 3+ verification checks execute:
        * Syntax AST parse check (PASSED)
        * Security static re-scan check (PASSED - vulnerability eradicated)
        * Regression check (PASSED - zero unintended findings introduced)
  14. Show the "Patch Validated" status badge.

[04:30 - 05:00] Repeatable Reset
  15. Click "Reset Demo" in the top bar to return the workspace to a pristine baseline.
```

---

## Supported Vulnerability Categories

VULNEX AI's static engine supports deterministic detection and remediation for:

| Category | CWE Identifier | Common Rule IDs | Detection Mechanism |
| :--- | :--- | :--- | :--- |
| **SQL Injection** | CWE-89 | `VULN-SQLI-001`, `B608` | AST taint tracking on `cursor.execute` with format/concatenation strings |
| **Command Injection** | CWE-78 | `VULN-CMDI-001`, `VULN-CMDI-002`, `B602` | AST inspection of `os.system` and `subprocess` with `shell=True` |
| **Hardcoded Credentials** | CWE-798 | `VULN-SECR-001`, `B105` | Shannon entropy analysis & regex inspection of API tokens/secrets |
| **Insecure Deserialization** | CWE-502 | `VULN-DESER-001`, `VULN-DESER-002`, `B301` | AST inspection of `pickle.loads` and `yaml.load` without SafeLoader |
| **Weak Cryptography** | CWE-327 | `VULN-CRYP-001`, `B303` | AST inspection of `hashlib.md5` and `hashlib.sha1` |
| **Code Evaluation** | CWE-95 | `VULN-EVAL-001`, `B307` | AST call inspection on dynamic `eval()` and `exec()` |

---

## Validation Pipeline & Limitations

### What Validation Checks Guarantee:
1. **Syntax Validity**: Proposed patches parse into valid AST without grammatical or structural corruption.
2. **Vulnerability Eradication**: Re-scanning the proposed patch with Bandit and AST checkers confirms the original rule violation is severed.
3. **Regression Prevention**: Re-scanning confirms no new security weaknesses or syntax errors were introduced.
4. **Isolate Safety**: Code checks run in a non-root, timeout-bounded temporary directory without host network, environment variables, or Docker socket access.

### Deliberate Limitations & What Remains Unverified:
- **No Dynamic Application Execution**: Submitted code is never executed inside the web server process.
- **Untrusted Unit Tests**: Dynamic runtime tests require containerization (e.g. gVisor / Firecracker) before executing arbitrary user test suites.
- **Human Review**: In production, automated validation does not replace developer review for business logic edge cases.

---

## Troubleshooting Guide

### 1. Frontend shows "API Disconnected"
- Ensure FastAPI server is running: `python -m uvicorn app.main:app --host 0.0.0.0 --port 8000`
- Confirm `frontend/.env` contains `VITE_API_BASE_URL=http://localhost:8000/api/v1`
- Test health directly in terminal: `curl http://localhost:8000/api/v1/health`

### 2. AI Provider shows "Configured (Untested)" or "Not Configured"
- If you have an API key, set `GEMINI_API_KEY=your_key` in `backend/.env` and restart the backend.
- If no API key is provided, VULNEX AI gracefully falls back to deterministic AST patch templates; the demo functions completely offline without requiring an external AI key.

### 3. Port Conflicts
- If port `8000` is occupied: `python -m uvicorn app.main:app --port 8001` and update `VITE_API_BASE_URL=http://localhost:8001/api/v1` in `frontend/.env`.
- If port `5173` is occupied, Vite will automatically select the next available port (e.g. `5174`).
