"""Authorized repository ingestion and scanning service."""

import logging
import os
import shutil
import subprocess
import tempfile
from typing import List, Optional
from urllib.parse import urlparse, urlunparse
from fastapi import HTTPException, status
from app.config import settings
from app.security.input_validation import validate_repository_url
from app.services.scanner import RawFinding, ScannerService

logger = logging.getLogger("vulnex.repository_service")

SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml"}


class RepositoryService:
    """Safely clones and scans authorized external git repositories."""

    @classmethod
    def clone_and_scan(
        cls,
        repo_url: str,
        branch: str = "main",
        auth_token: Optional[str] = None
    ) -> List[RawFinding]:
        # Validate URL for SSRF, schema, and forbidden IP addresses
        validate_repository_url(repo_url)

        # Build authenticated clone URL if token provided
        clone_url = repo_url
        if auth_token:
            parsed = urlparse(repo_url)
            # Embed token safely for git clone (e.g. https://token@github.com/...)
            netloc = f"{auth_token}@{parsed.netloc}"
            clone_url = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))

        temp_dir = tempfile.mkdtemp(prefix="vulnex_repo_")
        findings: List[RawFinding] = []

        try:
            # Execute shallow clone with bounded timeout and no execution of untrusted repo hooks
            git_cmd = [
                "git", "clone",
                "--depth", "1",
                "--branch", branch,
                "--config", "core.hooksPath=/dev/null",  # Disable git hooks for security
                clone_url,
                temp_dir
            ]

            try:
                proc = subprocess.run(
                    git_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=settings.repo_clone_timeout_seconds,
                    check=True
                )
            except subprocess.TimeoutExpired:
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail=f"Repository clone exceeded timeout of {settings.repo_clone_timeout_seconds} seconds."
                )
            except subprocess.CalledProcessError as e:
                # Sanitize error to avoid leaking auth_token
                err_msg = e.stderr.decode("utf-8", errors="replace")
                if auth_token:
                    err_msg = err_msg.replace(auth_token, "***")
                logger.error(f"Git clone error: {err_msg}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to clone repository. Verify URL, branch name, and authorization credentials."
                )

            # Traverse directory safely with file size and type boundaries
            total_size = 0
            for root, _, files in os.walk(temp_dir):
                # Skip .git directory
                if ".git" in root.split(os.sep):
                    continue

                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in SUPPORTED_EXTENSIONS:
                        file_path = os.path.join(root, file)
                        try:
                            file_size = os.path.getsize(file_path)
                            total_size += file_size

                            if total_size > settings.max_repo_clone_size_bytes:
                                raise HTTPException(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    detail=f"Repository source files exceed max size limit of {settings.max_repo_clone_size_bytes} bytes."
                                )

                            if file_size > settings.max_scan_file_size_bytes:
                                continue  # Skip individual oversized files

                            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                                content = f.read()

                            rel_path = os.path.relpath(file_path, temp_dir)
                            file_findings = ScannerService.scan_code(
                                source_code=content,
                                file_path=rel_path,
                                language="python" if ext == ".py" else "javascript"
                            )
                            findings.extend(file_findings)
                        except Exception as e:
                            logger.warning(f"Error scanning file {file}: {e}")

            return findings

        finally:
            # Ephemeral cleanup
            shutil.rmtree(temp_dir, ignore_errors=True)
