"""Input validation and security guardrails for Vulnex AI."""

import ipaddress
import os
import re
import socket
from urllib.parse import urlparse
from fastapi import HTTPException, status
from app.config import settings

# Disallowed hostnames or private ranges for SSRF prevention
BLOCKED_HOSTNAMES = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"}


def validate_source_code_size(code: str) -> None:
    """Validates that source code does not exceed max file size limits."""
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source code cannot be empty."
        )
    byte_len = len(code.encode("utf-8"))
    if byte_len > settings.max_scan_file_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Source code size ({byte_len} bytes) exceeds limit of {settings.max_scan_file_size_bytes} bytes."
        )


def sanitize_filename(filename: str) -> str:
    """Sanitizes filename to prevent directory traversal attacks."""
    if not filename:
        return "snippet.py"
    # Take only the basename and remove dangerous characters
    basename = os.path.basename(filename.replace("\\", "/"))
    clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", basename)
    return clean_name or "snippet.py"


def validate_repository_url(url: str) -> str:
    """
    Validates a repository URL to ensure:
    - Scheme is HTTPS only
    - No SSRF to local/private network addresses
    - Valid git repository domain structure
    """
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Repository URL is required."
        )

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only secure HTTPS repository URLs are supported (e.g. https://github.com/org/repo.git)."
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid repository URL hostname."
        )

    if hostname.lower() in BLOCKED_HOSTNAMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access to internal, loopback, or cloud metadata hosts is forbidden."
        )

    # Check if host resolves to private/loopback IP
    try:
        resolved_ips = socket.gethostbyname_ex(hostname)[2]
        for ip_str in resolved_ips:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Repository host resolves to disallowed private IP range ({ip_str})."
                )
    except socket.gaierror:
        # If hostname cannot be resolved, reject
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Repository hostname '{hostname}' could not be resolved."
        )

    return url


def sanitize_prompt_content(content: str) -> str:
    """
    Sanitizes untrusted source content to prevent prompt injection attacks against LLMs.
    Wraps code and neutralizes markdown injection delimiters.
    """
    if not content:
        return ""
    # Neutralize XML / system-level prompt tags if an adversary attempts to inject <system> or ```
    sanitized = content.replace("```", "'''")
    sanitized = re.sub(r"<\s*system\s*>", "[system]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"<\s*/\s*system\s*>", "[/system]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"<\s*assistant\s*>", "[assistant]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"<\s*/\s*assistant\s*>", "[/assistant]", sanitized, flags=re.IGNORECASE)
    return sanitized
