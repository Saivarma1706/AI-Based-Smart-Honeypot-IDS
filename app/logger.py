"""Logging utilities for the Smart Honeypot IDS.


Why logging matters in cybersecurity:
- Intrusion monitoring relies on a history of events (what happened and when).
- Logs help you detect patterns like brute-force attempts and suspicious behavior.
- Logs are the input for later analysis (manual review or automated tooling).

Beginner log analysis basics:
- Start by filtering for the *event type* (e.g., LOGIN_ATTEMPT, THREAT_ALERT).
- Check timestamps to see sequences (failed logins -> detection -> alert).
- Correlate by IP address and username to understand attacker behavior.
"""

from __future__ import annotations

import logging
import os

try:
    from .config import LOG_DIR, LOG_PATH
except ImportError:  # pragma: no cover
    from config import LOG_DIR, LOG_PATH


# Ensure log directory exists.  Wrapped in try/except so that an unwritable
# runtime directory (e.g. a read-only Program Files install in a PyInstaller
# build) does not crash the process at import time.
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    _log_file_path = LOG_PATH
except (OSError, PermissionError):
    print(
        f"[logger] WARNING: cannot create log dir {LOG_DIR!r}; "
        f"falling back to console-only logging.",
        flush=True,
    )
    _log_file_path = None


# Configure logging once.
# NOTE: In a real production service you might use RotatingFileHandler.
# In a frozen build, fall back to console-only logging if the log file path
# cannot be created or opened.
if _log_file_path is not None:
    try:
        logging.basicConfig(
            filename=_log_file_path,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )
    except (OSError, PermissionError):
        print(
            f"[logger] WARNING: cannot open log file {_log_file_path!r}; "
            f"using console-only logging.",
            flush=True,
        )
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def log_attempt(
    username: str,
    ip: str,
    success: bool,
    suspicious: bool = False,
    ai_prediction: str | None = None,
    threat_level: str | None = None,
) -> None:

    """Log login attempt outcome.

    Required fields (per project request):
    - timestamp (added by logging formatter)
    - username
    - IP address
    - login status
    - suspicious activity (boolean flag)
    """

    status = "SUCCESS" if success else "FAILED"

    # Beginner-friendly structured log line (easy to grep).
    # We keep existing fields and add the optional ones when provided.
    logging.info(
        "LOGIN_ATTEMPT username=%s ip=%s status=%s suspicious=%s ai_prediction=%s threat_level=%s",
        username,
        ip,
        status,
        str(bool(suspicious)).lower(),
        ai_prediction or "-",
        threat_level or "-",
    )



def log_threat(
    ip: str,
    alert_type: str,
    severity: int,
    details: str,
) -> None:
    """Log generated threat alerts."""

    # Replace newlines so the log stays on one line per event.
    safe_details = (details or "").replace(chr(10), " | ")
    logging.warning(
        "THREAT_ALERT ip=%s type=%s severity=%s details=%s",
        ip,
        alert_type,
        severity,
        safe_details,
    )


