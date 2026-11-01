# VULNEX AI — Demonstration Fixtures

Safe, intentionally vulnerable code examples and their secure counterparts designed specifically for live hackathon presentations and automated test verifications.

> [!IMPORTANT]
> All credentials used across these fixtures are **100% synthetic mock tokens** (`synthetic_demo_api_key_...`). No real secrets, production credentials, or exploit payloads are included.

---

## Fixture Catalog

| Vulnerable Fixture | Secure Counterpart | CWE ID & Title | Scanner Rule ID | Severity |
| :--- | :--- | :--- | :--- | :--- |
| `sql_injection_vulnerable.py` | `sql_injection_secure.py` | **CWE-89**: SQL Injection | `VULN-SQLI-001` | `CRITICAL` |
| `hardcoded_credential_vulnerable.py` | `hardcoded_credential_secure.py` | **CWE-798**: Hard-coded Credentials | `VULN-SECR-001` | `HIGH` |

---

## 1. SQL Injection (`CWE-89`)

### Vulnerable Pattern (`sql_injection_vulnerable.py`)
```python
query = f"SELECT id, username, email, role FROM users WHERE id = '{user_id}'"
cursor.execute(query)
```
- **Why Flagged**: Dynamic string interpolation via f-strings inside `cursor.execute` allows user parameters to alter the abstract syntax tree of the database query.
- **Scanner Detection**: Flagged by Bandit (`B608:hardcoded_sql_expressions`) and AST parser (`VULN-SQLI-001`).

### Secure Pattern (`sql_injection_secure.py`)
```python
query = "SELECT id, username, email, role FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```
- **How Remediated**: Uses parameterized query placeholders (`?` in SQLite, `%s` in PostgreSQL). Parameter bindings are passed via the DB driver wire protocol separately from query parsing.

---

## 2. Hardcoded Credential (`CWE-798`)

### Vulnerable Pattern (`hardcoded_credential_vulnerable.py`)
```python
api_key = "synthetic_demo_api_key_vulnex_hackathon_998877"
```
- **Why Flagged**: Hardcoded sensitive string assignment embedded in client code.
- **Scanner Detection**: Flagged by Bandit (`B105:hardcoded_password_string`) and Regex Scanner (`VULN-SECR-001`).

### Secure Pattern (`hardcoded_credential_secure.py`)
```python
self.api_key = os.getenv("PAYMENT_GATEWAY_API_KEY", "")
```
- **How Remediated**: Loads credential dynamically from process environment variables, preventing secret leakage in source repositories.

---

## How to Run in a Live Demo

1. Open the VULNEX AI Web UI at [http://localhost:5173](http://localhost:5173).
2. Ensure the top navigation indicates `🟢 LIVE API`.
3. Navigate to **New Scan** and select **Source Code Submission**.
4. Paste the content of `examples/sql_injection_vulnerable.py` (or click the quick preset button).
5. Click **Start Security Scan** and observe real-time scanning logs.
6. Click **Inspect Findings** to examine CWE metadata and scanner evidence.
7. Click **Remediate with AI** to synthesize the secure patch and view the unified diff.
8. Click **Validate Patch** to execute the isolated validation harness.
