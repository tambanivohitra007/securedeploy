"""Credential and secret redaction for logs and evidence output.

Applied before any user-visible output or log write.
Never modifies findings data — only display/log copies.
"""

from __future__ import annotations

import re

# Authorization header values
_AUTH_HEADER_RE = re.compile(
    r"(Authorization:\s*(?:Bearer|Basic|Token|ApiKey)\s+)[^\s\r\n]+",
    re.IGNORECASE,
)
# Cookie header values
_COOKIE_HEADER_RE = re.compile(r"(Cookie:\s*)[^\r\n]+", re.IGNORECASE)
# Set-Cookie values
_SET_COOKIE_RE = re.compile(r"(Set-Cookie:\s*[^=]+=)[^\s;]+", re.IGNORECASE)
# Common secret-looking key=value patterns in URLs and bodies
_SECRET_KV_RE = re.compile(
    r"((?:password|passwd|secret|token|key|api_key|apikey|access_token|auth)"
    r'\s*[=:]\s*["\']?)'
    r"[^\s&\"\',}\]]{4,}",
    re.IGNORECASE,
)
# AWS access key pattern
_AWS_KEY_RE = re.compile(r"(AKIA|ASIA|AROA)[0-9A-Z]{16}")
# Generic high-entropy strings that look like tokens (36+ hex chars)
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{36,}\b")

REDACTED = "<redacted>"


def redact(text: str) -> str:
    """Apply all redaction patterns to a string."""
    text = _AUTH_HEADER_RE.sub(r"\1" + REDACTED, text)
    text = _COOKIE_HEADER_RE.sub(r"\1" + REDACTED, text)
    text = _SET_COOKIE_RE.sub(r"\1" + REDACTED, text)
    text = _SECRET_KV_RE.sub(r"\1" + REDACTED, text)
    text = _AWS_KEY_RE.sub(REDACTED, text)
    return text


def redact_dict(d: dict) -> dict:
    """Recursively redact a dict (for structured log entries)."""
    sensitive_keys = {
        "password", "passwd", "secret", "token", "key", "api_key", "apikey",
        "access_token", "refresh_token", "authorization", "cookie", "auth",
        "private_key", "client_secret",
    }
    result = {}
    for k, v in d.items():
        if isinstance(k, str) and k.lower() in sensitive_keys:
            result[k] = REDACTED
        elif isinstance(v, dict):
            result[k] = redact_dict(v)
        elif isinstance(v, str):
            result[k] = redact(v)
        else:
            result[k] = v
    return result
