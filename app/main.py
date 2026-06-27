from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import Flask, render_template, request, redirect, session, url_for


try:
    # When executed as a module: python -m app.main
    from .alerts import create_alert_for_detection
    from .attacks_db import init_attacks_db

    from .auth import validate_login
    from .ai_model import ai_predict_label_and_score
    from .config import BRUTE_FORCE_WINDOW_SECONDS, RECENT_ATTEMPTS_LIMIT
    from .database import init_db, insert_login_attempt, fetch_recent_attempts_by_ip
    from .detector import evaluate_suspicion
    from .logger import log_attempt
    from .security_pipeline import process_security_event
    from .utils import build_features, ip_normalize
except ImportError:  # pragma: no cover
    # When executed as a script: python app/main.py
    from alerts import create_alert_for_detection
    from attacks_db import init_attacks_db
    from ai_model import ai_predict_label_and_score
    from auth import validate_login

    from config import BRUTE_FORCE_WINDOW_SECONDS, RECENT_ATTEMPTS_LIMIT
    from database import init_db, insert_login_attempt, fetch_recent_attempts_by_ip
    from detector import evaluate_suspicion
    from logger import log_attempt
    from security_pipeline import process_security_event
    from utils import build_features, ip_normalize


import os
import sys

if getattr(sys, "frozen", False):
    BASE_DIR = getattr(sys, "_MEIPASS")
else:
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

print("=" * 50)
print("MAIN FILE:", __file__)
print("BASE_DIR:", BASE_DIR)
print("TEMPLATE_DIR:", TEMPLATE_DIR)
print("LOGIN_EXISTS:", os.path.exists(os.path.join(TEMPLATE_DIR, "login.html")))
print("=" * 50)

# Integrity verification BEFORE Flask initialization.
# Requirement: if any hash mismatch is detected, block startup.
try:
    from .integrity import verify_or_raise_on_startup
except ImportError:  # pragma: no cover
    from integrity import verify_or_raise_on_startup

verify_or_raise_on_startup()


app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
)


# Session authentication (dashboard protection)

# 30 minutes timeout
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.secret_key = os.environ.get("SECRET_KEY") or "dev-only-insecure-secret-please-override"

# CSRF protection (Flask-WTF)
try:
    from flask_wtf.csrf import CSRFProtect

    CSRFProtect(app)
except Exception:
    # If Flask-WTF isn't available, the app still boots, but CSRF will be missing.
    # (Task requirements expect Flask-WTF to be installed.)
    pass

try:
    from .csrf_utils import register_csrf_error_handler

    register_csrf_error_handler(app)
except Exception:
    pass


@app.before_request
def _startup() -> None:

    # Ensure DB schema exists. Runs on first request in dev.
    init_db()

    # Also ensure attacks dashboard schema exists.
    # (init_attacks_db imported at module scope for PyInstaller safety.)
    try:
        init_attacks_db()
    except Exception:
        pass



try:
    # Prefer package-relative import when running from the project root
    from .dashboard_routes import register_dashboard_routes
except ImportError:  # pragma: no cover
    # Fallback for legacy "python app/main.py" execution
    from dashboard_routes import register_dashboard_routes

register_dashboard_routes(app)

try:
    from .service_routes import register_service_routes
except ImportError:  # pragma: no cover
    from service_routes import register_service_routes

register_service_routes(app)



@app.route("/", methods=["GET", "POST"])
def login():

    """Honeypot admin login page.

    Pipeline (runs on POST):
    1) read username/password and client IP
    2) SHA256 auth check
    3) persist login attempt in SQLite
    4) run detector on recent attempts for this IP
    5) if suspicious/bruteforce -> generate threat alert
    6) render safe message
    """

    message = ""
    ip = ""

    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Capture IP address (real deployment may use ProxyFix / X-Forwarded-For)
        ip = ip_normalize(request.remote_addr)

        success = validate_login(username=username, password=password)

        if success:
            failure_reason = None
        else:
            failure_reason = "INVALID_CREDENTIALS"

        # Delegate detection, AI scoring, rate limiting, and alert generation
        # to the shared security pipeline (same path used by /ssh, /database,
        # /server, /api/auth). This brings Phase 5 rate-limit enforcement
        # to the main login route and populates service_route/event_type.
        result = process_security_event(
            raw_ip=request.remote_addr,
            username=username,
            password=password,
            success=success,
            failure_reason=failure_reason,
            service_route="/",
            request_path=request.path,
            event_type="ADMIN_LOGIN",
        )

        if result.blocked:
            message = "Too many failed attempts. Try again later."
        else:
            if result.success:
                session.clear()
                session.permanent = True
                session["logged_in"] = True
                session["username"] = username
            # UI message should not reveal detection details
            message = "Login Successful" if result.success else "Invalid Credentials"

        log_attempt(
            username=username,
            ip=request.remote_addr or "unknown",
            success=result.success,
            suspicious=result.suspicious,
            ai_prediction=result.ai_label,
            threat_level=str(result.ai_score),
        )

    return render_template(
        "login.html",
        message=message,
        # ip is optional for debugging; template can ignore it.
        ip=ip,
        username=session.get("username", ""),
    )



if __name__ == "__main__":
    # Use fixed host/port and disable reloader to avoid double-start.
    print("[startup] Starting Flask server on http://127.0.0.1:5000")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=(os.environ.get("FLASK_ENV", "development") == "development"),
        use_reloader=False,
    )


  