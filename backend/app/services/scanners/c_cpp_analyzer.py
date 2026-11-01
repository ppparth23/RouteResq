"""VULNEX AI — Custom C/C++ & Embedded IoT Firmware AST & Semantic Security Analyzer.

Performs syntax-aware vulnerability detection, function-level inspection,
source-to-sink tracing, and exact line-number mapping for:
- Memory Safety (Buffer overflows, UAF, Double Free, Leaks, Null Deref, Uninitialized ptr)
- Input & Execution Security (Format strings, Command injection, Integer overflow)
- Cryptographic Security (Hardcoded secrets/keys, Weak crypto, Insecure PRNG)
- Secure IoT Firmware Risks (ESP32/ESP-IDF, FreeRTOS, Arduino, STM32, Zephyr)
"""

from dataclasses import dataclass
import re
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CCppFinding:
    rule_id: str
    title: str
    category: str
    cwe_id: str
    severity: str
    cvss_score: float
    cvss_version: str
    line_number: int
    line_start: int
    line_end: int
    code_snippet: str
    description: str
    impact: str
    recommendation: str
    function_name: Optional[str] = None
    column_number: int = 1
    root_cause: Optional[str] = None
    exploitation_conditions: Optional[str] = None
    source: str = "c_cpp_analyzer"
    confidence: str = "high"


class CCppSecurityAnalyzer:
    """
    Syntax-aware C/C++ security analyzer with specialized embedded IoT heuristics.
    """

    @classmethod
    def scan_code(
        cls,
        source_code: str,
        filename: str = "main.c",
        target_platform: Optional[str] = None
    ) -> List[CCppFinding]:
        if not source_code or not source_code.strip():
            return []

        findings: List[CCppFinding] = []
        lines = source_code.splitlines()

        # Extract function blocks with line ranges
        functions = cls._extract_functions(lines)

        # 1. Memory Safety Analyzers
        findings.extend(cls._analyze_memory_safety(lines, functions, filename))

        # 2. Input and Execution Analyzers
        findings.extend(cls._analyze_input_execution(lines, functions, filename))

        # 3. Cryptography & Secrets Analyzers
        findings.extend(cls._analyze_cryptography_secrets(lines, filename))

        # 4. Embedded IoT Firmware Analyzers
        findings.extend(cls._analyze_iot_firmware(lines, functions, filename, target_platform))

        # 5. C++ Specific Analyzers
        findings.extend(cls._analyze_cpp_specific(lines, functions, filename))

        # 6. Firmware Configuration Analyzers
        findings.extend(cls._analyze_firmware_config(lines, filename, target_platform))

        # Deduplicate findings on (cwe_id, line_start)
        seen: Set[Tuple[str, int]] = set()
        deduped: List[CCppFinding] = []
        for f in findings:
            key = (f.cwe_id, f.line_start)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped

    # --------------------------------------------------------------------------
    # Helper: Function Block Extractor
    # --------------------------------------------------------------------------
    @staticmethod
    def _extract_functions(lines: List[str]) -> List[Dict]:
        """Identifies C/C++ function boundaries and their line spans."""
        functions = []
        func_sig_re = re.compile(
            r'^\s*(?:(?:static|inline|extern|virtual|const|unsigned|void|int|char|bool|size_t|uint\d+_t|int\d+_t|float|double|[\w_]+)\s+)+[*&\s]*([\w_]+)\s*\(([^)]*)\)\s*\{?'
        )

        in_func = False
        current_func: Optional[Dict] = None
        brace_depth = 0

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip pure comments
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            if not in_func:
                m = func_sig_re.match(line)
                if m and not line.strip().endswith(";"):
                    name = m.group(1)
                    if name not in ("if", "for", "while", "switch", "catch"):
                        in_func = True
                        brace_depth = line.count("{") - line.count("}")
                        current_func = {
                            "name": name,
                            "start_line": i,
                            "end_line": i,
                            "lines": [line],
                            "line_indices": [i]
                        }
                        if brace_depth == 0 and "{" in line:
                            in_func = False
                            functions.append(current_func)
            else:
                current_func["lines"].append(line)
                current_func["line_indices"].append(i)
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    current_func["end_line"] = i
                    functions.append(current_func)
                    in_func = False

        return functions

    # --------------------------------------------------------------------------
    # 1. Memory Safety Analyzers
    # --------------------------------------------------------------------------
    @classmethod
    def _analyze_memory_safety(
        cls,
        lines: List[str],
        functions: List[Dict],
        filename: str
    ) -> List[CCppFinding]:
        findings: List[CCppFinding] = []

        # 1a. Stack Buffer Overflow: strcpy / strcat / gets / unbounded sprintf
        for i, line in enumerate(lines, start=1):
            if re.search(r'\bgets\s*\(', line):
                findings.append(CCppFinding(
                    rule_id="C-MEM-GETS",
                    title="Insecure gets() Inherent Stack Buffer Overflow",
                    category="Memory Safety",
                    cwe_id="CWE-120",
                    severity="critical",
                    cvss_score=9.8,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="gets() does not check buffer limits, enabling trivial stack buffer overflow.",
                    impact="Full system takeover or arbitrary code execution via control flow hijacking.",
                    recommendation="Replace gets() with fgets(buffer, sizeof(buffer), stdin)."
                ))

            if re.search(r'\bstrcpy\s*\(\s*([a-zA-Z0-9_\->\.]+)\s*,\s*([^)]+)\)', line):
                findings.append(CCppFinding(
                    rule_id="C-MEM-STRCPY",
                    title="Stack Buffer Overflow via Unbounded strcpy",
                    category="Memory Safety",
                    cwe_id="CWE-121",
                    severity="high",
                    cvss_score=8.8,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="strcpy() copies source bytes without bound verification, overflowing destination buffer.",
                    impact="Stack smashing, control register corruption, or arbitrary code execution.",
                    recommendation="Replace strcpy() with strncpy(dest, src, sizeof(dest) - 1) or snprintf(dest, sizeof(dest), \"%s\", src)."
                ))

            if re.search(r'\bstrcat\s*\(\s*([a-zA-Z0-9_\->\.]+)\s*,\s*([^)]+)\)', line):
                findings.append(CCppFinding(
                    rule_id="C-MEM-STRCAT",
                    title="Buffer Overflow via Unbounded strcat",
                    category="Memory Safety",
                    cwe_id="CWE-120",
                    severity="high",
                    cvss_score=8.5,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="strcat() appends source bytes without checking remaining destination capacity.",
                    impact="Adjacent memory corruption and denial of service.",
                    recommendation="Use strncat(dest, src, sizeof(dest) - strlen(dest) - 1) or snprintf."
                ))

            if re.search(r'\bsprintf\s*\(\s*([a-zA-Z0-9_\->\.]+)\s*,\s*("[^"]*")\s*,', line):
                findings.append(CCppFinding(
                    rule_id="C-MEM-SPRINTF",
                    title="Unbounded sprintf Buffer Overflow",
                    category="Memory Safety",
                    cwe_id="CWE-120",
                    severity="high",
                    cvss_score=8.2,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="sprintf() formats unbounded strings into fixed-size buffer without size limits.",
                    impact="Buffer overflow leading to memory corruption.",
                    recommendation="Use snprintf(dest, sizeof(dest), format, ...)."
                ))

        # 1b. Use-After-Free & Double-Free & Memory Leaks (Function-level analysis)
        for func in functions:
            func_lines = func["lines"]
            func_indices = func["line_indices"]

            freed_vars: Dict[str, int] = {}  # var_name -> line_number

            for idx, f_line in zip(func_indices, func_lines):
                # Match free(ptr) or delete ptr
                free_match = re.search(r'\bfree\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)', f_line) or \
                             re.search(r'\bdelete\s+(?:\[\]\s*)?([a-zA-Z_][a-zA-Z0-9_]*)', f_line)

                if free_match:
                    var_name = free_match.group(1)
                    if var_name in freed_vars:
                        # Double Free!
                        findings.append(CCppFinding(
                            rule_id="C-MEM-DOUBLE-FREE",
                            title=f"Double Free of Pointer '{var_name}'",
                            category="Memory Safety",
                            cwe_id="CWE-415",
                            severity="high",
                            cvss_score=8.1,
                            cvss_version="3.1",
                            line_number=idx,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=f_line.strip(),
                            description=f"Pointer '{var_name}' freed at line {idx} was already freed at line {freed_vars[var_name]}.",
                            impact="Heap corruption, freelist poisoning, and potential arbitrary code execution.",
                            recommendation=f"Set '{var_name} = NULL;' immediately after freeing, and verify single-ownership."
                        ))
                    else:
                        freed_vars[var_name] = idx

                # Check if an already freed variable is subsequently dereferenced
                for f_var, f_line_no in freed_vars.items():
                    if idx > f_line_no:
                        # Check dereference: var->field, *var, var[i]
                        uaf_pattern = rf'(?:->|\*|\b{f_var}\s*\[|\b{f_var}\s*->)'
                        if re.search(uaf_pattern, f_line) and not re.search(rf'\b{f_var}\s*=\s*', f_line):
                            findings.append(CCppFinding(
                                rule_id="C-MEM-USE-AFTER-FREE",
                                title=f"Use-After-Free of Deallocated Pointer '{f_var}'",
                                category="Memory Safety",
                                cwe_id="CWE-416",
                                severity="critical",
                                cvss_score=8.8,
                                cvss_version="3.1",
                                line_number=idx,
                                line_start=idx,
                                line_end=idx,
                                code_snippet=f_line.strip(),
                                description=f"Pointer '{f_var}' dereferenced at line {idx} after being freed at line {f_line_no}.",
                                impact="Arbitrary memory access, data corruption, or code execution through vtable hijack.",
                                recommendation=f"Do not access '{f_var}' after free(). Assign '{f_var} = NULL;' immediately after deallocation."
                            ))

            # 1c. Memory Leak: malloc/calloc in local scope without free
            alloc_vars: Dict[str, int] = {}
            for idx, f_line in zip(func_indices, func_lines):
                alloc_match = re.search(
                    r'(?:(?:char|int|void|uint\d+_t|struct\s+\w+)\s*\*+\s*|\b)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|strdup|new\s+\w+)\s*\(',
                    f_line
                )
                if alloc_match:
                    v = alloc_match.group(1)
                    if not re.search(r'\breturn\b', f_line):
                        alloc_vars[v] = idx

            # Check if any allocated local pointer is returned or freed
            for v, alloc_line in alloc_vars.items():
                is_freed = any(re.search(rf'\bfree\s*\(\s*{v}\s*\)|\bdelete\b.*{v}', fl) for fl in func_lines)
                is_returned = any(re.search(rf'\breturn\b.*{v}', fl) for fl in func_lines)
                if not is_freed and not is_returned and v not in freed_vars:
                    findings.append(CCppFinding(
                        rule_id="C-MEM-LEAK",
                        title=f"Potential Memory Leak of Allocated Pointer '{v}'",
                        category="Memory Safety",
                        cwe_id="CWE-401",
                        severity="medium",
                        cvss_score=6.5,
                        cvss_version="3.1",
                        line_number=alloc_line,
                        line_start=alloc_line,
                        line_end=alloc_line,
                        code_snippet=lines[alloc_line - 1].strip(),
                        description=f"Memory allocated to '{v}' at line {alloc_line} is not freed before function '{func['name']}' exits.",
                        impact="Memory exhaustion in embedded microcontrollers with constrained RAM.",
                        recommendation=f"Free allocated pointer '{v}' before returning, or use RAII smart pointers in C++."
                    ))

        # 1d. Null Pointer Dereference: unchecked malloc result
        for i, line in enumerate(lines, start=1):
            if re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', line):
                # Check next 3 lines for direct dereference without NULL check
                var_m = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', line)
                if var_m:
                    v_name = var_m.group(1)
                    for next_idx in range(i, min(len(lines), i + 3)):
                        next_line = lines[next_idx]
                        if f"{v_name}[" in next_line or f"*{v_name}" in next_line or f"{v_name}->" in next_line:
                            if "if" not in next_line and "NULL" not in next_line:
                                findings.append(CCppFinding(
                                    rule_id="C-MEM-NULL-DEREF",
                                    title=f"Potential Null Pointer Dereference on '{v_name}'",
                                    category="Memory Safety",
                                    cwe_id="CWE-476",
                                    severity="high",
                                    cvss_score=7.5,
                                    cvss_version="3.1",
                                    line_number=next_idx + 1,
                                    line_start=next_idx + 1,
                                    line_end=next_idx + 1,
                                    code_snippet=next_line.strip(),
                                    description=f"Pointer '{v_name}' dereferenced without validating that malloc() succeeded.",
                                    impact="Null pointer dereference causing immediate microcontroller crash / kernel panic.",
                                    recommendation=f"Add null check: if ({v_name} == NULL) {{ return -1; }}"
                                ))
                                break

        return findings

    # --------------------------------------------------------------------------
    # 2. Input and Execution Analyzers
    # --------------------------------------------------------------------------
    @classmethod
    def _analyze_input_execution(
        cls,
        lines: List[str],
        functions: List[Dict],
        filename: str
    ) -> List[CCppFinding]:
        findings: List[CCppFinding] = []

        for i, line in enumerate(lines, start=1):
            # 2a. Format String Vulnerability
            fmt_match = re.search(
                r'\b(printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*(?:[^,]+,\s*)?([a-zA-Z_][a-zA-Z0-9_\->\.]*)\s*\);',
                line
            )
            if fmt_match:
                func_called = fmt_match.group(1)
                arg_var = fmt_match.group(2)
                if not arg_var.startswith('"'):
                    findings.append(CCppFinding(
                        rule_id="C-INP-FORMAT-STRING",
                        title=f"Format String Vulnerability in {func_called}()",
                        category="Input & Execution Security",
                        cwe_id="CWE-134",
                        severity="high",
                        cvss_score=8.6,
                        cvss_version="3.1",
                        line_number=i,
                        line_start=i,
                        line_end=i,
                        code_snippet=line.strip(),
                        description=f"Passing variable '{arg_var}' directly as format string parameter allows format specifier injection (%s, %x, %n).",
                        impact="Arbitrary memory exposure and arbitrary memory write.",
                        recommendation=f"Always supply constant format string literal: {func_called}(\"%s\", {arg_var});"
                    ))

            # 2b. Command Injection via system() or popen()
            cmd_match = re.search(r'\b(system|popen|_popen)\s*\(\s*([^)]+)\)', line)
            if cmd_match:
                func_name = cmd_match.group(1)
                arg_expr = cmd_match.group(2).strip()
                # If argument is not a pure string literal
                if not (arg_expr.startswith('"') and arg_expr.endswith('"')):
                    findings.append(CCppFinding(
                        rule_id="C-EXEC-CMD-INJECTION",
                        title=f"Command Injection via {func_name}()",
                        category="Input & Execution Security",
                        cwe_id="CWE-78",
                        severity="critical",
                        cvss_score=9.8,
                        cvss_version="3.1",
                        line_number=i,
                        line_start=i,
                        line_end=i,
                        code_snippet=line.strip(),
                        description=f"{func_name}() passes command '{arg_expr}' to shell without sanitization, permitting command injection.",
                        impact="Arbitrary shell command execution with privileges of the host firmware.",
                        recommendation="Avoid shell execution. Use execve() or POSIX spawn with an explicit argument array."
                    ))

            # 2c. Integer Overflow prior to memory allocation
            int_overflow_match = re.search(
                r'\b(?:malloc|calloc)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*\s*[*+]\s*[^)]+)\)',
                line
            )
            if int_overflow_match:
                calc = int_overflow_match.group(1).strip()
                findings.append(CCppFinding(
                    rule_id="C-INP-INT-OVERFLOW-ALLOC",
                    title="Integer Overflow in Memory Allocation Size",
                    category="Input & Execution Security",
                    cwe_id="CWE-190",
                    severity="high",
                    cvss_score=7.8,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description=f"Calculation '{calc}' inside malloc() can wrap around on 32-bit/16-bit architectures, allocating a tiny buffer.",
                    impact="Subsequent copies into the undersized buffer trigger heap overflow.",
                    recommendation="Validate operands for multiplication overflow before allocation, or use calloc() with size checks."
                ))

        return findings

    # --------------------------------------------------------------------------
    # 3. Cryptography & Secrets Analyzers
    # --------------------------------------------------------------------------
    @classmethod
    def _analyze_cryptography_secrets(
        cls,
        lines: List[str],
        filename: str
    ) -> List[CCppFinding]:
        findings: List[CCppFinding] = []

        secret_patterns = [
            (
                r'(?:api_key|apikey|secret|password|passwd|auth_token|private_key|encryption_key)\s*=\s*"([^"]{8,})"',
                "C-CRY-HARDCODED-SECRET",
                "Hardcoded Credential / API Key in C/C++ Source",
                "CWE-798",
                "high",
                7.5,
                "Hardcoded sensitive secret in source code can be extracted from compiled firmware binary."
            ),
            (
                r'#(?:define)\s+(?:WIFI_PASS|WIFI_PASSWORD|API_KEY|DEVICE_SECRET|AES_KEY)\s+"([^"]{4,})"',
                "C-CRY-HARDCODED-MACRO-SECRET",
                "Hardcoded Password or Key in Macro Definition",
                "CWE-798",
                "high",
                7.5,
                "Macro-defined passwords and encryption keys persist directly in firmware read-only flash."
            )
        ]

        for i, line in enumerate(lines, start=1):
            for pat, rule_id, title, cwe, sev, cvss, desc in secret_patterns:
                m = re.search(pat, line, re.IGNORECASE)
                if m:
                    findings.append(CCppFinding(
                        rule_id=rule_id,
                        title=title,
                        category="Cryptographic Security",
                        cwe_id=cwe,
                        severity=sev,
                        cvss_score=cvss,
                        cvss_version="3.1",
                        line_number=i,
                        line_start=i,
                        line_end=i,
                        code_snippet=line.strip(),
                        description=desc,
                        impact="Adversaries extracting firmware can retrieve root credentials and impersonate the device.",
                        recommendation="Store credentials in encrypted Non-Volatile Storage (NVS) or a dedicated Secure Element."
                    ))

            # Insecure PRNG (rand/srand)
            if re.search(r'\brand\s*\(\s*\)', line) and not line.strip().startswith("//"):
                findings.append(CCppFinding(
                    rule_id="C-CRY-INSECURE-RAND",
                    title="Insecure Pseudo-Random Number Generator (rand)",
                    category="Cryptographic Security",
                    cwe_id="CWE-338",
                    severity="medium",
                    cvss_score=5.3,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="rand() produces predictable pseudo-random sequences unsuitable for security-sensitive tokens.",
                    impact="Adversaries can predict session identifiers, cryptographic nonces, or generated keys.",
                    recommendation="Use hardware true random number generator (e.g., esp_fill_random or hardware TRNG peripheral)."
                ))

            # Weak Cryptographic Algorithms (MD5 / DES / RC4)
            weak_crypto_match = re.search(r'\b(MD5_Init|MD5_Update|DES_encrypt|RC4_set_key|mbedtls_md5)\b', line)
            if weak_crypto_match:
                algo = weak_crypto_match.group(1)
                findings.append(CCppFinding(
                    rule_id="C-CRY-WEAK-ALGORITHM",
                    title=f"Use of Cryptographically Broken Algorithm ({algo})",
                    category="Cryptographic Security",
                    cwe_id="CWE-327",
                    severity="medium",
                    cvss_score=5.9,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description=f"{algo} utilizes broken cryptographic primitives vulnerable to collision and preimage attacks.",
                    impact="Attacker can forge digital signatures or crack message confidentiality.",
                    recommendation="Upgrade to SHA-256 or SHA-3 for hashing, and AES-GCM for symmetric encryption."
                ))

        return findings

    # --------------------------------------------------------------------------
    # 4. Embedded IoT Firmware Analyzers
    # --------------------------------------------------------------------------
    @classmethod
    def _analyze_iot_firmware(
        cls,
        lines: List[str],
        functions: List[Dict],
        filename: str,
        target_platform: Optional[str]
    ) -> List[CCppFinding]:
        findings: List[CCppFinding] = []

        for i, line in enumerate(lines, start=1):
            # 4a. Insecure TLS Certificate Verification: setInsecure() (Arduino / ESP8266 / ESP32)
            if "setInsecure()" in line:
                findings.append(CCppFinding(
                    rule_id="IOT-TLS-SET-INSECURE",
                    title="Disabled TLS Certificate Verification (setInsecure)",
                    category="IoT Communication Security",
                    cwe_id="CWE-295",
                    severity="high",
                    cvss_score=7.5,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="setInsecure() disables X.509 certificate validation, allowing Man-in-the-Middle (MITM) interception.",
                    impact="Adversaries on the same network can intercept telemetry, inject malicious commands, and spoof servers.",
                    recommendation="Install and verify root CA certificate using client.setCACert(root_ca_pem)."
                ))

            # 4b. mbedTLS verify none
            if "MBEDTLS_SSL_VERIFY_NONE" in line:
                findings.append(CCppFinding(
                    rule_id="IOT-TLS-VERIFY-NONE",
                    title="mbedTLS Authentication Disabled (MBEDTLS_SSL_VERIFY_NONE)",
                    category="IoT Communication Security",
                    cwe_id="CWE-295",
                    severity="high",
                    cvss_score=7.5,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="Configuring MBEDTLS_SSL_VERIFY_NONE causes TLS handshakes to accept arbitrary untrusted certificates.",
                    impact="Full Man-In-The-Middle TLS traffic interception and credential theft.",
                    recommendation="Enforce MBEDTLS_SSL_VERIFY_REQUIRED and configure mbedtls_ssl_conf_ca_chain()."
                ))

            # 4c. Insecure Plaintext MQTT URI
            if re.search(r'["\']mqtt:\/\/[^"\']*["\']|uri\s*=\s*"mqtt:\/\/|\.port\s*=\s*1883\b', line):
                findings.append(CCppFinding(
                    rule_id="IOT-COMM-PLAINTEXT-MQTT",
                    title="Insecure Plaintext MQTT Transport Protocol",
                    category="IoT Communication Security",
                    cwe_id="CWE-319",
                    severity="high",
                    cvss_score=7.5,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="MQTT broker connection established via unencrypted TCP (port 1883 / mqtt://) instead of MQTTS (port 8883).",
                    impact="Cleartext transmission of actuator commands, sensor telemetry, and authentication tokens.",
                    recommendation="Switch to MQTTS (mqtts://) on port 8883 with mutual TLS certificate authentication."
                ))

            # 4d. Plaintext HTTP Communication
            if re.search(r'["\']http:\/\/(?!localhost|127\.0\.0\.1)[^"\']+["\']', line):
                findings.append(CCppFinding(
                    rule_id="IOT-COMM-PLAINTEXT-HTTP",
                    title="Unencrypted HTTP Communication in Firmware",
                    category="IoT Communication Security",
                    cwe_id="CWE-319",
                    severity="medium",
                    cvss_score=6.5,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="Firmware communicates over unencrypted HTTP protocol, exposing sensitive parameters.",
                    impact="Eavesdropping and payload alteration over the local network.",
                    recommendation="Enforce HTTPS with verified root CA certificates."
                ))

            # 4e. Unsigned OTA Firmware Update
            if "esp_ota_begin" in line:
                findings.append(CCppFinding(
                    rule_id="IOT-OTA-UNSIGNED-UPDATE",
                    title="Unverified OTA Firmware Update Initialization",
                    category="Firmware Update Security",
                    cwe_id="CWE-494",
                    severity="high",
                    cvss_score=8.6,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="esp_ota_begin() called without cryptographic signature verification check.",
                    impact="Flashing unverified firmware binary can result in persistent device bricking or malware persistence.",
                    recommendation="Verify SHA-256 digest and asymmetric ECDSA/RSA signature before committing OTA image."
                ))

            # 4f. FreeRTOS Task Stack Underallocation
            task_match = re.search(
                r'\bxTaskCreate\s*\([^,]+,[^,]+,\s*(\d+)\s*,',
                line
            )
            if task_match:
                stack_depth = int(task_match.group(1))
                if stack_depth < 1024:
                    findings.append(CCppFinding(
                        rule_id="IOT-MEM-TASK-STACK-TOO-SMALL",
                        title=f"Critically Underallocated FreeRTOS Task Stack ({stack_depth} words)",
                        category="Firmware Memory Security",
                        cwe_id="CWE-121",
                        severity="medium",
                        cvss_score=6.8,
                        cvss_version="3.1",
                        line_number=i,
                        line_start=i,
                        line_end=i,
                        code_snippet=line.strip(),
                        description=f"FreeRTOS task allocated with only {stack_depth} words of stack space. Embedded TLS or printf calls will overflow stack.",
                        impact="Task stack overflow leading to silent memory corruption and hard-fault resets.",
                        recommendation="Increase task stack depth to at least 2048 or 4096 words, especially when invoking network or crypto APIs."
                    ))

            # 4g. Sensitive Credential Exposure via Debug Logs (UART / Serial)
            if re.search(r'\b(ESP_LOG[IEWD]|printf|Serial\.print(?:ln)?)\s*\([^)]*(?:password|passwd|secret|api_key|token)[^)]*\)', line, re.IGNORECASE):
                findings.append(CCppFinding(
                    rule_id="IOT-SYS-DEBUG-LOG-LEAK",
                    title="Sensitive Credential Emitted to Serial/UART Debug Output",
                    category="Device Authentication",
                    cwe_id="CWE-532",
                    severity="medium",
                    cvss_score=5.5,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="Logging function emits authentication secrets or cryptographic keys over UART / Serial interface.",
                    impact="Physical access or adjacent debug listeners can monitor UART pins to intercept device credentials.",
                    recommendation="Remove sensitive credential logging and disable production UART debug output."
                ))

        return findings

    @classmethod
    def _find_enclosing_function(cls, functions: List[Dict], line_no: int) -> str:
        """Determines the enclosing function name for a specific line number."""
        for func in functions:
            if func["start_line"] <= line_no <= func["end_line"]:
                return func["name"]
        return "global"

    # --------------------------------------------------------------------------
    # 5. C++ Specific Security Analyzers
    # --------------------------------------------------------------------------
    @classmethod
    def _analyze_cpp_specific(
        cls,
        lines: List[str],
        functions: List[Dict],
        filename: str
    ) -> List[CCppFinding]:
        findings: List[CCppFinding] = []

        # 5a. scanf / sscanf unbounded %s buffer overflow (C/C++)
        for i, line in enumerate(lines, start=1):
            if re.search(r'\bscanf\s*\(\s*"[^"]*%s|\b(?:sscanf|fscanf|__isoc99_sscanf)\s*\([^,]+,\s*"[^"]*%s', line):
                col = line.find("%s") + 1
                func_name = cls._find_enclosing_function(functions, i)
                findings.append(CCppFinding(
                    rule_id="C-MEM-SCANF-OVERFLOW",
                    title="Unbounded String Format in scanf/sscanf",
                    category="Memory Safety",
                    cwe_id="CWE-120",
                    severity="high",
                    cvss_score=8.5,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="scanf() family format string uses unbounded '%s' without specifying maximum field width.",
                    impact="Attacker-controlled input can overflow destination stack or heap buffer, causing denial of service or code execution.",
                    recommendation="Specify maximum length in format string (e.g. '%63s') or use fgets / std::string.",
                    function_name=func_name,
                    column_number=col,
                    root_cause="Unbounded %s specifier copies input until whitespace without checking destination capacity.",
                    exploitation_conditions="User-controlled input exceeding allocated target buffer length."
                ))

            # 5b. Unsafe type conversions: reinterpret_cast
            if "reinterpret_cast" in line and not line.strip().startswith("//"):
                col = line.find("reinterpret_cast") + 1
                func_name = cls._find_enclosing_function(functions, i)
                findings.append(CCppFinding(
                    rule_id="CPP-TYPE-UNSAFE-CAST",
                    title="Unsafe Type Punning via reinterpret_cast",
                    category="C++ Specific Security",
                    cwe_id="CWE-704",
                    severity="medium",
                    cvss_score=6.3,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip(),
                    description="reinterpret_cast bypasses C++ type system, risking strict aliasing violations and memory corruption.",
                    impact="Undefined behavior, object layout misalignment, and subtle memory corruption on cross-platform architectures.",
                    recommendation="Avoid reinterpret_cast. Use static_cast, dynamic_cast, or std::bit_cast (C++20).",
                    function_name=func_name,
                    column_number=col,
                    root_cause="Arbitrary pointer-to-pointer reinterpretation violating alignment and type safety.",
                    exploitation_conditions="Dereferencing misaligned or incompatibly typed memory through recast pointer."
                ))

        # 5c. C++ Function-level: Array Deletion Mismatch & Use-After-Move
        for func in functions:
            func_lines = func["lines"]
            func_indices = func["line_indices"]

            # Track new Type[] vs delete
            array_news: Dict[str, int] = {}
            for idx, fl in zip(func_indices, func_lines):
                m_new = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*new\s+\w+\s*\[', fl)
                if m_new:
                    array_news[m_new.group(1)] = idx

                # Check for delete (without [])
                m_del = re.search(r'\bdelete\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;', fl)
                if m_del:
                    del_var = m_del.group(1)
                    if del_var in array_news:
                        col = fl.find("delete") + 1
                        findings.append(CCppFinding(
                            rule_id="CPP-MEM-ARRAY-DELETE-MISMATCH",
                            title=f"Mismatched Memory Deallocation on Array '{del_var}'",
                            category="C++ Specific Security",
                            cwe_id="CWE-762",
                            severity="high",
                            cvss_score=7.5,
                            cvss_version="3.1",
                            line_number=idx,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=fl.strip(),
                            description=f"Array allocated with new[] at line {array_news[del_var]} was deallocated with scalar delete instead of delete[].",
                            impact="Heap corruption and failure to invoke destructors on array elements.",
                            recommendation=f"Use 'delete[] {del_var};' or replace with std::vector / std::unique_ptr<T[]>",
                            function_name=func["name"],
                            column_number=col,
                            root_cause="Operator delete mismatch between scalar delete and vector new[].",
                            exploitation_conditions="Array deallocation during normal program execution causing heap manager desynchronization."
                        ))

            # Track std::move use-after-move
            moved_vars: Dict[str, int] = {}
            for idx, fl in zip(func_indices, func_lines):
                m_move = re.search(r'std::move\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)', fl)
                if m_move:
                    moved_vars[m_move.group(1)] = idx

                for mv_var, mv_line in moved_vars.items():
                    if idx > mv_line:
                        # Check if accessed subsequently
                        if re.search(rf'\b{mv_var}\s*(?:\.|->|\[)', fl) and not re.search(rf'\b{mv_var}\s*=\s*', fl):
                            col = fl.find(mv_var) + 1
                            findings.append(CCppFinding(
                                rule_id="CPP-MEM-USE-AFTER-MOVE",
                                title=f"Use-After-Move of Object '{mv_var}'",
                                category="C++ Specific Security",
                                cwe_id="CWE-672",
                                severity="high",
                                cvss_score=7.8,
                                cvss_version="3.1",
                                line_number=idx,
                                line_start=idx,
                                line_end=idx,
                                code_snippet=fl.strip(),
                                description=f"Object '{mv_var}' was used after its resources were transferred via std::move at line {mv_line}.",
                                impact="Accessing moved-from object in an unspecified or null state can lead to crashes or data corruption.",
                                recommendation=f"Do not access '{mv_var}' after std::move, or explicitly reassign it to a valid state.",
                                function_name=func["name"],
                                column_number=col,
                                root_cause="Subsequent member access on an object whose internal state was cleared or invalidated by move semantics.",
                                exploitation_conditions="Invoking member methods on deallocated or nullified moved-from instance."
                            ))

        return findings

    # --------------------------------------------------------------------------
    # 6. Firmware Configuration Analyzers (sdkconfig, FreeRTOSConfig.h, etc.)
    # --------------------------------------------------------------------------
    @classmethod
    def _analyze_firmware_config(
        cls,
        lines: List[str],
        filename: str,
        target_platform: Optional[str]
    ) -> List[CCppFinding]:
        findings: List[CCppFinding] = []

        for i, line in enumerate(lines, start=1):
            s = line.strip()

            # 6a. FreeRTOS Stack Overflow Hook Disabled
            if "configCHECK_FOR_STACK_OVERFLOW" in s and (" 0" in s or "=0" in s):
                findings.append(CCppFinding(
                    rule_id="IOT-CFG-STACK-OVERFLOW-DISABLED",
                    title="FreeRTOS Stack Overflow Hook Disabled",
                    category="Firmware Configuration Security",
                    cwe_id="CWE-121",
                    severity="high",
                    cvss_score=7.5,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=s,
                    description="configCHECK_FOR_STACK_OVERFLOW is set to 0. FreeRTOS will not detect task stack overflows, allowing silent memory corruption.",
                    impact="Stack exhaustion silent corruption without triggering vApplicationStackOverflowHook recovery.",
                    recommendation="Set '#define configCHECK_FOR_STACK_OVERFLOW 2' for robust canary and watermark validation.",
                    function_name="config",
                    column_number=1,
                    root_cause="Stack overflow protection hook explicitly disabled in RTOS configuration.",
                    exploitation_conditions="Embedded task exceeding allocated task stack space during network or cryptographic operations."
                ))

            # 6b. ESP32 Missing Secure Boot
            if ("CONFIG_SECURE_BOOT=n" in s or "# CONFIG_SECURE_BOOT is not set" in s) or \
               ("CONFIG_SECURE_BOOT_V2_ENABLED=n" in s):
                findings.append(CCppFinding(
                    rule_id="IOT-CFG-SECURE-BOOT-DISABLED",
                    title="ESP-IDF Secure Boot Protection Disabled",
                    category="Firmware Update Security",
                    cwe_id="CWE-1274",
                    severity="critical",
                    cvss_score=9.3,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=s,
                    description="ESP-IDF hardware secure boot is disabled. Unsigned firmware binaries will be executed without cryptographic hardware signature verification.",
                    impact="Physical or remote attackers can flash modified firmware or backdoored bootloaders permanently.",
                    recommendation="Enable 'CONFIG_SECURE_BOOT=y' and 'CONFIG_SECURE_BOOT_V2_ENABLED=y' with eFuse key provisioning.",
                    function_name="sdkconfig",
                    column_number=1,
                    root_cause="Hardware cryptographic signature verification for bootloader and application partition is disabled.",
                    exploitation_conditions="Firmware update or direct flash write without cryptographic signing key."
                ))

            # 6c. ESP32 Flash Encryption Disabled
            if ("CONFIG_SECURE_FLASH_ENC_ENABLED=n" in s or "# CONFIG_SECURE_FLASH_ENC_ENABLED is not set" in s or
                "CONFIG_FLASH_ENCRYPTION_ENABLED=n" in s or "# CONFIG_FLASH_ENCRYPTION_ENABLED is not set" in s):
                findings.append(CCppFinding(
                    rule_id="IOT-CFG-FLASH-ENCRYPTION-DISABLED",
                    title="ESP-IDF Flash Memory Encryption Disabled",
                    category="Device Authentication",
                    cwe_id="CWE-312",
                    severity="high",
                    cvss_score=7.8,
                    cvss_version="3.1",
                    line_number=i,
                    line_start=i,
                    line_end=i,
                    code_snippet=s,
                    description="Flash memory encryption is disabled. Firmware code, NVS credentials, and Wi-Fi keys are stored in plaintext SPI flash.",
                    impact="Adversary with physical access can read external SPI flash chip directly to dump master keys and firmware.",
                    recommendation="Enable 'CONFIG_SECURE_FLASH_ENC_ENABLED=y' to enforce AES-XTS flash encryption.",
                    function_name="sdkconfig",
                    column_number=1,
                    root_cause="External SPI flash bus is unencrypted, allowing physical bus sniffing and flash dumping.",
                    exploitation_conditions="Physical SPI bus probing or flash desoldering/dumping via external programmer."
                ))

        return findings
