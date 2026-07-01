from __future__ import annotations

"""Flask routes for the multi-service honeypot simulation."""

from flask import Blueprint, jsonify, render_template, request

try:
    from .auth import validate_login
    from .logger import log_attempt
    from .security_pipeline import process_security_event
except ImportError:  # pragma: no cover
    from auth import validate_login
    from logger import log_attempt
    from security_pipeline import process_security_event


def register_service_routes(app) -> None:
    bp = Blueprint("services", __name__)

    @bp.route("/ssh", methods=["GET", "POST"])
    def ssh_portal():
        message = ""
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")

            success = validate_login(username=username, password=password)
            failure_reason = None if success else "InvalidCredentials"

            result = process_security_event(
                raw_ip=request.remote_addr,
                username=username,
                password=password,
                success=success,
                failure_reason=failure_reason,
                service_route="/ssh",
                request_path=request.path,
                event_type="SSH_AUTH",
            )

            if getattr(result, "blocked", False):
                message = "Too many failed attempts. Try again later."
            else:
                # Keep UI generic; never expose AI labels.
                message = "Access Granted" if result.success else "Authentication Failed"

            log_attempt(

                username=username,
                ip=request.remote_addr or "unknown",
                success=result.success,
                suspicious=result.suspicious,
                ai_prediction=result.ai_label,
                threat_level=str(result.ai_score),
            )

        return render_template("ssh.html", message=message)

    @bp.route("/database", methods=["GET", "POST"])
    def database_console():
        message = ""
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")

            success = validate_login(username=username, password=password)
            failure_reason = None if success else "DBAAuthenticationFailed"

            result = process_security_event(
                raw_ip=request.remote_addr,
                username=username,
                password=password,
                success=success,
                failure_reason=failure_reason,
                service_route="/database",
                request_path=request.path,
                event_type="DBA_LOGIN",
            )

            if getattr(result, "blocked", False):
                message = "Too many failed attempts. Try again later."
            else:
                message = "Database Session Established" if result.success else "Access Denied"

            log_attempt(
                username=username,
                ip=request.remote_addr or "unknown",
                success=result.success,
                suspicious=result.suspicious,
                ai_prediction=result.ai_label,
                threat_level=str(result.ai_score),
            )

        return render_template("database.html", message=message)

    @bp.route("/server", methods=["GET", "POST"])
    def server_portal():
        message = ""
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")

            success = validate_login(username=username, password=password)
            failure_reason = None if success else "ServerAdminAuthFailed"

            result = process_security_event(
                raw_ip=request.remote_addr,
                username=username,
                password=password,
                success=success,
                failure_reason=failure_reason,
                service_route="/server",
                request_path=request.path,
                event_type="INFRA_ADMIN_LOGIN",
            )

            if getattr(result, "blocked", False):
                message = "Too many failed attempts. Try again later."
            else:
                message = "Admin Console Unlocked" if result.success else "Login Rejected"

            log_attempt(
                username=username,
                ip=request.remote_addr or "unknown",
                success=result.success,
                suspicious=result.suspicious,
                ai_prediction=result.ai_label,
                threat_level=str(result.ai_score),
            )

        return render_template("server.html", message=message)

    @bp.route("/api", methods=["GET"])
    def api_portal():
        return render_template("api.html")

    @bp.route("/api/auth", methods=["POST"])
    def api_auth():
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))

        success = validate_login(username=username, password=password)
        failure_reason = None if success else "InvalidApiCredentials"

        result = process_security_event(
            raw_ip=request.remote_addr,
            username=username,
            password=password,
            success=success,
            failure_reason=failure_reason,
            service_route="/api/auth",
            request_path=request.path,
            event_type="API_AUTH",
        )

        # JSON response that does not leak details.
        if getattr(result, "blocked", False):
            response = {
                "ok": False,
                "message": "Too many failed attempts. Temporarily blocked.",
                "temporary_block": True,
            }
            return jsonify(response), 429

        response = {
            "ok": bool(result.success),
            "message": "Authentication successful" if result.success else "Authentication failed",
            "temporary_block": False,
        }

        # Optional: log suspicious API requests into normal app logs.
        if result.suspicious or not result.success:
            log_attempt(

                username=username,
                ip=request.remote_addr or "unknown",
                success=result.success,
                suspicious=result.suspicious,
                ai_prediction=result.ai_label,
                threat_level=str(result.ai_score),
            )

        return jsonify(response), (200 if result.success else 401)

    app.register_blueprint(bp)

