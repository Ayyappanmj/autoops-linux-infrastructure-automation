"""Shared helpers: exit codes, secret redaction, JSON read/write."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_FINDINGS = 1  # drift / non-compliance / failed validation
EXIT_INPUT_ERROR = 2  # bad usage, missing or invalid input

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}


class AutoOpsError(Exception):
    """Base class for expected, user-facing errors."""


class InputError(AutoOpsError):
    """Missing, unreadable or invalid input."""


_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b(\s*[=:]\s*)(\S+)"), r"\1\2[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED AWS KEY ID]"),
]


def redact(text: str) -> str:
    """Mask obvious secrets before text is printed or logged."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def utc_now_iso(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).isoformat(timespec="seconds")


def read_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.is_file():
        raise InputError(f"input file not found: {p}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {p}: {exc}") from exc
    except OSError as exc:
        raise InputError(f"cannot read {p}: {exc}") from exc


def write_json(path: str | Path, data: Any, overwrite: bool = False) -> Path:
    """Write JSON; refuses to replace an existing file unless overwrite=True."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if overwrite else "x"
    try:
        with open(p, mode, encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=False)
            fh.write("\n")
    except FileExistsError as exc:
        raise InputError(f"refusing to overwrite existing file: {p} (use --force)") from exc
    return p
