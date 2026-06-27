from __future__ import annotations

"""CSRF helpers.

Kept as a tiny module so we can wire CSRF error handling without touching
existing AI/detector/dashboard/attack simulator logic.
"""

import logging
from flask import Flask, render_template_string, request

try:
    from .logger import log_attempt
except ImportError:  # pragma: no cover
    from logger import log_attempt


def register_csrf_error_handler(app: Flask) -> None:
    """Register a custom handler for invalid/missing CSRF tokens."""

    @app.errorhandler(400)
    def _csrf_custom_400_handler(e):  # noqa: ANN001
        # Flask-WTF uses 400 for CSRF failures.
        # We detect CSRF by message prefix.
        msg = str(getattr(e, "description", ""))
        if "The CSRF token" in msg or "CSRF" in msg or "csrf" in msg:
            try:
                # (log_attempt imported at module scope for PyInstaller safety.)
                log_attempt(
                    username=request.form.get("username", "unknown") or "unknown",
                    ip=request.remote_addr or "unknown",
                    success=False,
                    suspicious=True,
                    ai_prediction="CSRF_VALIDATION_FAILED",
                    threat_level="0",
                )
            except Exception:
                logging.exception("Failed to log CSRF validation failure")

            # DEBUG MODE ONLY: reveal actual CSRF failure reason
            return render_template_string(
                f"<h2>CSRF Validation Failed</h2><p>{msg}</p>"
            ), 400

        # Non-CSRF 400: re-raise default handling by returning generic message.
        return render_template_string("Security validation failed"), 400


