"""Sandbox and isolated code verification utilities for Vulnex AI.

Enforces zero arbitrary code execution on the API host:
1. Static non-executing AST syntax verification (eval/exec banned).
2. Explicit detection of secure isolated container environments (Docker/Podman).
3. Hardened container execution flags (--network=none, non-root, read-only rootfs, memory/CPU/PID limits).
4. Refusal to run untrusted dynamic tests if a secure sandbox is unavailable (no silent host fallback).
5. Output sanitization redacting host paths and environment secrets.
"""

import ast
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple


class SandboxUnavailableError(RuntimeError):
    """Raised when an execution-based check is requested but no isolated sandbox is available."""
    pass


def check_syntax_safely(source_code: str, language: str = "python") -> Tuple[bool, Optional[str]]:
    """
    Checks if code is syntactically valid using static AST parsing without executing it.
    Never calls eval() or exec().
    """
    if not source_code:
        return False, "Source code is empty"

    lang = (language or "python").lower()

    if lang in ("python", "py"):
        try:
            ast.parse(source_code)
            return True, None
        except SyntaxError as e:
            return False, f"Python SyntaxError at line {e.lineno}, offset {e.offset}: {e.msg}"
        except Exception as e:
            return False, f"AST parsing error: {str(e)}"

    # For C and C++ languages: static structural and syntax verification
    if lang in ("c", "cpp", "c++", "h", "hpp"):
        # 1. If clang or gcc is present on host, attempt static compilation check with -fsyntax-only (no execution)
        clang_bin = shutil.which("clang") or shutil.which("gcc")
        if clang_bin:
            try:
                import tempfile
                ext = ".cpp" if "cpp" in lang or "c++" in lang else ".c"
                with tempfile.NamedTemporaryFile(suffix=ext, mode="w", delete=False, encoding="utf-8") as tf:
                    tf.write(source_code)
                    tf_name = tf.name
                try:
                    res = subprocess.run(
                        [clang_bin, "-fsyntax-only", tf_name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,
                        encoding="utf-8",
                        errors="replace"
                    )
                    if res.returncode == 0:
                        return True, None
                    else:
                        err_line = res.stderr.splitlines()[0] if res.stderr.splitlines() else "Compilation syntax error"
                        return False, sanitize_execution_output(err_line)
                finally:
                    if os.path.exists(tf_name):
                        os.unlink(tf_name)
            except Exception:
                pass  # Fall back to structural parser

        # 2. Structural syntax validation (braces, parens, brackets, unclosed literals, macros)
        stack = []
        brackets = {')': '(', '}': '{', ']': '['}
        in_string = False
        in_char = False
        in_line_comment = False
        in_block_comment = False
        escape = False
        line_num = 1
        col_num = 0
        directive_stack = []

        chars = list(source_code)
        i = 0
        n = len(chars)

        while i < n:
            c = chars[i]
            col_num += 1

            if c == '\n':
                line_num += 1
                col_num = 0
                in_line_comment = False
                escape = False
                i += 1
                continue

            if in_line_comment:
                i += 1
                continue

            if in_block_comment:
                if c == '*' and i + 1 < n and chars[i + 1] == '/':
                    in_block_comment = False
                    i += 2
                    col_num += 1
                    continue
                i += 1
                continue

            if escape:
                escape = False
                i += 1
                continue

            if c == '\\':
                escape = True
                i += 1
                continue

            if in_string:
                if c == '"':
                    in_string = False
                i += 1
                continue

            if in_char:
                if c == "'":
                    in_char = False
                i += 1
                continue

            # Check comments
            if c == '/' and i + 1 < n:
                if chars[i + 1] == '/':
                    in_line_comment = True
                    i += 2
                    col_num += 1
                    continue
                elif chars[i + 1] == '*':
                    in_block_comment = True
                    i += 2
                    col_num += 1
                    continue

            if c == '"':
                in_string = True
                i += 1
                continue

            if c == "'":
                in_char = True
                i += 1
                continue

            # Bracket matching
            if c in '({[':
                stack.append((c, line_num, col_num))
            elif c in ')}]':
                if not stack:
                    return False, f"C/C++ SyntaxError at line {line_num}: unmatched closing bracket '{c}'."
                open_b, o_line, _ = stack.pop()
                if open_b != brackets[c]:
                    return False, f"C/C++ SyntaxError at line {line_num}: bracket mismatch. Expected matching for '{open_b}' from line {o_line}, found '{c}'."

            # Preprocessor check
            if c == '#' and col_num == 1:
                # Read directive
                rest = "".join(chars[i:i+30]).split()
                if rest:
                    d = rest[0].lower()
                    if d in ("#if", "#ifdef", "#ifndef"):
                        directive_stack.append((d, line_num))
                    elif d == "#endif":
                        if not directive_stack:
                            return False, f"C/C++ Preprocessor error at line {line_num}: #endif without #if/#ifdef."
                        directive_stack.pop()

            i += 1

        if in_string:
            return False, "C/C++ SyntaxError: Unterminated string literal."
        if in_char:
            return False, "C/C++ SyntaxError: Unterminated character literal."
        if in_block_comment:
            return False, "C/C++ SyntaxError: Unterminated /* block comment."
        if stack:
            open_b, o_line, _ = stack[-1]
            return False, f"C/C++ SyntaxError: Unclosed bracket '{open_b}' opened at line {o_line}."
        if directive_stack:
            d, d_line = directive_stack[-1]
            return False, f"C/C++ Preprocessor error: Unclosed '{d}' directive from line {d_line}."

        return True, None

    # For other languages (e.g. javascript/typescript/json), structural check
    if lang in ("javascript", "typescript", "js", "ts"):
        stack = []
        brackets = {')': '(', '}': '{', ']': '['}
        for char in source_code:
            if char in '({[':
                stack.append(char)
            elif char in ')}]':
                if not stack or stack.pop() != brackets[char]:
                    return False, f"Unmatched bracket '{char}' detected."
        return True, None

    return True, None


def is_secure_sandbox_available() -> Tuple[bool, str]:
    """
    Verifies whether a hardened isolated container engine (e.g. Docker or Podman) is available
    to run untrusted code under non-root and network-restricted containment.
    """
    # Check for docker or podman in PATH
    docker_bin = shutil.which("docker") or shutil.which("podman")
    if not docker_bin:
        return False, "Container runtime (Docker/Podman) is not installed or not in PATH."

    try:
        res = subprocess.run(
            [docker_bin, "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=False
        )
        if res.returncode == 0:
            return True, f"Container engine '{os.path.basename(docker_bin)}' is active and available."
        else:
            return False, f"Container engine '{os.path.basename(docker_bin)}' is not responsive."
    except Exception as e:
        return False, f"Container engine check failed: {type(e).__name__}"


def run_in_secure_sandbox(
    command: List[str],
    workspace_dir: str,
    timeout_seconds: int = 15,
    memory_limit: str = "256m",
    cpu_limit: str = "0.5",
    pids_limit: int = 50
) -> Tuple[int, str, str]:
    """
    Executes a trusted test command inside a strictly isolated container sandbox.
    Constraints:
    - Non-root execution (--user 1000:1000)
    - No network access (--network=none)
    - Read-only root filesystem (--read-only)
    - CPU limit (--cpus)
    - Memory limit (--memory)
    - Process limit (--pids-limit)
    - Clean ephemeral mount for workspace_dir only
    - Stripped environment (no host API keys or tokens)

    Raises SandboxUnavailableError if no container engine is reachable.
    """
    available, reason = is_secure_sandbox_available()
    if not available:
        raise SandboxUnavailableError(
            f"Cannot execute untrusted code on host: {reason}. "
            "Refusing execution to maintain server security."
        )

    docker_bin = shutil.which("docker") or shutil.which("podman")
    container_image = "python:3.12-slim"

    docker_cmd = [
        docker_bin, "run", "--rm",
        "--network=none",
        "--user=1000:1000",
        "--read-only",
        f"--memory={memory_limit}",
        f"--cpus={cpu_limit}",
        f"--pids-limit={pids_limit}",
        "-v", f"{os.path.abspath(workspace_dir)}:/workspace:rw",
        "-w", "/workspace",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        container_image
    ] + command

    try:
        proc = subprocess.run(
            docker_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            encoding="utf-8",
            errors="replace"
        )
        stdout = sanitize_execution_output(proc.stdout)
        stderr = sanitize_execution_output(proc.stderr)
        return proc.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        return -1, "", f"Execution timed out after {timeout_seconds} seconds inside isolated sandbox."
    except Exception as e:
        return -1, "", f"Sandbox execution failure: {str(e)}"


def sanitize_execution_output(text: str) -> str:
    """
    Sanitizes execution output to prevent leakage of host paths, usernames, or secrets.
    """
    if not text:
        return ""

    sanitized = text
    # Redact user directory paths (e.g. C:\Users\payya or /home/username)
    user_home = os.path.expanduser("~")
    if user_home and len(user_home) > 3:
        sanitized = sanitized.replace(user_home, "[HOST_USER_HOME]")

    # Redact common credential patterns (AI keys, bearer tokens)
    sanitized = re.sub(r'AIza[0-9A-Za-z-_]{35}', '[REDACTED_API_KEY]', sanitized)
    sanitized = re.sub(r'ghp_[0-9A-Za-z]{36}', '[REDACTED_GITHUB_TOKEN]', sanitized)
    sanitized = re.sub(r'(?:api[_-]?key|secret|token)\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.]{8,}["\']?', '[REDACTED_SECRET]', sanitized, flags=re.IGNORECASE)

    return sanitized
