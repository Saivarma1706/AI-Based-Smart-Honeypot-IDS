"""app.dashboard_routes

Flask route handlers for the Smart Honeypot IDS dashboard.

Beginner-friendly architecture:
- app/main.py remains the entry point for the Flask app.
- This file contains just the dashboard logic and template rendering.
- All metrics are fetched dynamically from SQLite.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from flask import redirect, render_template, request, session, url_for

try:
    from .attacks_db import (
        fetch_recent_attacks,
        fetch_attacks_stats,
        init_attacks_db,
        fetch_failed_login_count,
        fetch_suspicious_ips,
        fetch_threat_level_distribution,
        fetch_top_attacking_ips,
        fetch_threat_alert_count_by_severity,
        fetch_service_activity_distribution,
        fetch_top_attacked_services,
        fetch_failed_attempts_by_service,
        fetch_threat_counts_by_service,
        fetch_hourly_attempt_volume,
        fetch_top_targeted_usernames,
        fetch_failure_reason_distribution,
        fetch_ip_summary,
        fetch_ip_block_record,
        fetch_ip_services_targeted,
        fetch_ip_usernames_targeted,
        fetch_ip_failure_reasons,
        fetch_ip_threat_alerts,
        fetch_ip_recent_activity,
    )
    from .rate_limit_db import (
        ip_is_currently_blocked,
        unblock_ip,
        fetch_blocked_ip_count,
        fetch_currently_blocked_ips,
        now_iso,
    )
    from .exports import (
        fetch_all_login_attempts,
        fetch_all_threat_alerts,
        fetch_all_suspicious_ips,
        stream_csv_response,
        build_security_report_pdf,
    )
    from .logger import log_attempt
except ImportError:  # pragma: no cover
    from attacks_db import (
        fetch_recent_attacks,
        fetch_attacks_stats,
        init_attacks_db,
        fetch_failed_login_count,
        fetch_suspicious_ips,
        fetch_threat_level_distribution,
        fetch_top_attacking_ips,
        fetch_threat_alert_count_by_severity,
        fetch_service_activity_distribution,
        fetch_top_attacked_services,
        fetch_failed_attempts_by_service,
        fetch_threat_counts_by_service,
        fetch_hourly_attempt_volume,
        fetch_top_targeted_usernames,
        fetch_failure_reason_distribution,
        fetch_ip_summary,
        fetch_ip_block_record,
        fetch_ip_services_targeted,
        fetch_ip_usernames_targeted,
        fetch_ip_failure_reasons,
        fetch_ip_threat_alerts,
        fetch_ip_recent_activity,
    )
    from rate_limit_db import (
        ip_is_currently_blocked,
        unblock_ip,
        fetch_blocked_ip_count,
        fetch_currently_blocked_ips,
        now_iso,
    )
    from exports import (
        fetch_all_login_attempts,
        fetch_all_threat_alerts,
        fetch_all_suspicious_ips,
        stream_csv_response,
        build_security_report_pdf,
    )
    from logger import log_attempt



def register_dashboard_routes(app) -> None:
    """Register dashboard route(s) on the provided Flask app instance."""

    @app.route("/logout", methods=["GET"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard", methods=["GET"])
    def dashboard():

        """
        Render cybersecurity monitoring dashboard.

        Fetches all metrics dynamically from SQLite:
        - Total/failed login attempts
        - Threat alerts and suspicious IPs
        - AI threat predictions
        - Recent attack activity
        - Threat level distribution
        """

        try:
            from datetime import datetime, timezone

            # DEBUG: confirm functions imported (avoid NameError due to import mismatches)
            print(
                "=== DASHBOARD IMPORT DEBUG ===\n",
                "fetch_service_activity_distribution=",
                fetch_service_activity_distribution,
            )

            # Ensure table exists

            init_attacks_db()

            # Fetch core attack statistics
            stats = fetch_attacks_stats()

            # Fetch additional metrics from login_attempts table
            failed_logins = fetch_failed_login_count()
            suspicious_ip_count = fetch_suspicious_ips()

            # Fetch threat level distribution (Safe/Suspicious/Threat)
            threat_distribution = fetch_threat_level_distribution()

            # Fetch top attacking IPs
            top_ips = fetch_top_attacking_ips(limit=8)

            # Fetch threat alert severity distribution
            severity_dist = fetch_threat_alert_count_by_severity()

            # Fetch recent attacks for activity table
            recent_attacks = fetch_recent_attacks(limit=25)

            # Calculate composite threat level indicator
            total_attempts = stats.get("total_attacks", 0)
            ai_threat_level = "Critical" if stats.get("threat_alerts", 0) > 10 else \
                              "High" if stats.get("suspicious_attempts", 0) > 5 else \
                              "Medium" if failed_logins > 3 else "Low"

            # Get current timestamp
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            # Phase-2 enterprise multi-service metrics (primary source of truth: login_attempts)
            service_activity_distribution = fetch_service_activity_distribution(limit=6)
            top_attacked_services = fetch_top_attacked_services(limit=5)
            failed_attempts_by_service = fetch_failed_attempts_by_service(limit=6)
            threat_counts_by_service = fetch_threat_counts_by_service(limit=6)

            # Phase 6 Task 1: Blocked IP Management (read path)
            # (rate_limit_db is imported at module scope above for PyInstaller safety.)
            _now = now_iso()
            blocked_ip_count = fetch_blocked_ip_count(_now)
            currently_blocked_ips = fetch_currently_blocked_ips(_now, limit=20)

            # Phase 6 Task 2: Advanced Analytics (read-only)
            hourly_attempt_volume = fetch_hourly_attempt_volume(hours=24)
            top_targeted_usernames = fetch_top_targeted_usernames(limit=10)
            failure_reason_distribution = fetch_failure_reason_distribution(limit=10)


            # Prepare dashboard data
            dashboard_data = {
                # Core statistics
                "total_attempts": total_attempts,
                "failed_logins": failed_logins,
                "threat_alerts": stats.get("threat_alerts", 0),
                "suspicious_ips": suspicious_ip_count,
                "ai_threat_level": ai_threat_level,

                # Threat distribution
                "threat_safe": threat_distribution.get("safe", 0),
                "threat_suspicious": threat_distribution.get("suspicious", 0),
                "threat_threat": threat_distribution.get("threat", 0),

                # Severity distribution
                "severity_distribution": severity_dist,

                # Recent activity
                "recent_attacks": recent_attacks,
                "top_attacking_ips": top_ips,

                # Phase-2 service metrics
                "service_activity_distribution": service_activity_distribution,
                "top_attacked_services": top_attacked_services,
                "failed_attempts_by_service": failed_attempts_by_service,
                "threat_counts_by_service": threat_counts_by_service,

                # Phase 6 Task 1: Blocked IP Management
                "blocked_ip_count": blocked_ip_count,
                "currently_blocked_ips": currently_blocked_ips,

                # Phase 6 Task 2: Advanced Analytics
                "hourly_attempt_volume": hourly_attempt_volume,
                "top_targeted_usernames": top_targeted_usernames,
                "failure_reason_distribution": failure_reason_distribution,

                # Overall statistics
                "stats": stats,
                "now": now,
            }


            # --- DEBUG BLOCK (temporary) ---
            print("=== DASHBOARD DEBUG ===")
            print("stats =", stats)
            print("failed_logins =", failed_logins)
            print("threat_distribution =", threat_distribution)
            print("recent_attacks_count =", len(recent_attacks))
            print("dashboard_data =", dashboard_data)


            # Session protection (deny if not authenticated)
            if not session.get("logged_in"):
                # Unauthorized dashboard access logging
                # (log_attempt is imported at module scope above for PyInstaller safety.)
                try:
                    import datetime
                    log_attempt(
                        username=session.get("username", "unknown"),
                        ip=request.remote_addr or "unknown",
                        success=False,
                        suspicious=True,
                        ai_prediction="DASHBOARD_UNAUTH",
                        threat_level="0",
                    )
                except Exception:
                    pass

                return redirect(url_for("login"))

            return render_template("dashboard.html", **dashboard_data)

        except Exception as e:
            import traceback
            print("DASHBOARD ERROR:")
            traceback.print_exc()
            raise

    @app.route("/dashboard/export/login_attempts.csv")
    def export_login_attempts_csv():
        """Phase 6 Task 3: full login_attempts dump as CSV."""
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        # (fetch_all_login_attempts / stream_csv_response imported at module scope.)
        limit = int(request.args.get("limit", 10000))
        offset = int(request.args.get("offset", 0))
        rows = fetch_all_login_attempts(limit=limit, offset=offset)
        return stream_csv_response(
            headers=[
                "id", "created_at", "ip", "username", "success", "failure_reason",
                "is_honeypot_target", "service_route", "request_path", "event_type",
            ],
            rows=[list(r.values()) for r in rows],
            filename="login_attempts.csv",
        )

    @app.route("/dashboard/export/threat_alerts.csv")
    def export_threat_alerts_csv():
        """Phase 6 Task 3: full threat_alerts dump as CSV."""
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        # (fetch_all_threat_alerts / stream_csv_response imported at module scope.)
        limit = int(request.args.get("limit", 10000))
        offset = int(request.args.get("offset", 0))
        rows = fetch_all_threat_alerts(limit=limit, offset=offset)
        return stream_csv_response(
            headers=["id", "created_at", "ip", "alert_type", "severity", "details"],
            rows=[list(r.values()) for r in rows],
            filename="threat_alerts.csv",
        )

    @app.route("/dashboard/export/suspicious_ips.csv")
    def export_suspicious_ips_csv():
        """Phase 6 Task 3: full suspicious_ips dump as CSV."""
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        # (fetch_all_suspicious_ips / stream_csv_response imported at module scope.)
        limit = int(request.args.get("limit", 10000))
        offset = int(request.args.get("offset", 0))
        rows = fetch_all_suspicious_ips(limit=limit, offset=offset)
        return stream_csv_response(
            headers=[
                "id", "ip", "failed_attempts", "threat_score",
                "blocked_until", "last_seen", "blocked_count",
            ],
            rows=[list(r.values()) for r in rows],
            filename="suspicious_ips.csv",
        )

    @app.route("/dashboard/export/report.pdf")
    def export_report_pdf():
        """Phase 6 Task 3: multi-section security report as PDF."""
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        from flask import Response
        # (build_security_report_pdf imported at module scope.)
        return Response(
            build_security_report_pdf(),
            mimetype="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="security_report.pdf"'},
        )

    @app.route("/dashboard/ip/<ip>", methods=["GET"])
    def ip_investigation_route(ip: str):
        """Phase 6 Task 4: per-IP threat investigation page.

        - Requires an authenticated session (same protection as /dashboard).
        - Returns 404 if the IP has no data in any of the three tables
          (login_attempts, threat_alerts, suspicious_ips).
        - Otherwise renders templates/ip_investigation.html with the
          per-IP summary, services, usernames, failure reasons, threat
          alerts, and recent activity timeline.
        """
        if not session.get("logged_in"):
            return redirect(url_for("login"))

        # (ip_is_currently_blocked / now_iso imported at module scope.)

        summary = fetch_ip_summary(ip)
        block_record = fetch_ip_block_record(ip)
        services = fetch_ip_services_targeted(ip)
        usernames = fetch_ip_usernames_targeted(ip)
        reasons = fetch_ip_failure_reasons(ip)
        alerts = fetch_ip_threat_alerts(ip, limit=50)
        activity = fetch_ip_recent_activity(ip, limit=50)

        # 404 if the IP is unknown to all three tables
        if (
            summary.get("total", 0) == 0
            and not block_record
            and len(alerts) == 0
        ):
            return render_template("ip_not_found.html", ip=ip), 404

        _now = now_iso()
        is_blocked = ip_is_currently_blocked(ip, _now)

        from datetime import datetime, timezone
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        return render_template(
            "ip_investigation.html",
            ip=ip,
            summary=summary,
            block_record=block_record,
            is_blocked=is_blocked,
            services=services,
            usernames=usernames,
            reasons=reasons,
            alerts=alerts,
            activity=activity,
            generated_at=generated_at,
        )

    @app.route("/dashboard/blocked-ips/<ip>/unblock", methods=["POST"])
    def unblock_ip_route(ip: str):
        """Phase 6 Task 1: manually unblock an IP from the dashboard.

        - Requires an authenticated session (same protection as /dashboard).
        - Calls rate_limit_db.unblock_ip() which sets blocked_until = NULL
          and preserves the lifetime blocked_count.
        - Logs the action via log_attempt with ai_prediction="ADMIN_UNBLOCK".
        - Redirects back to /dashboard with an anchor to the panel.
        """
        if not session.get("logged_in"):
            return redirect(url_for("login"))

        # (unblock_ip / log_attempt imported at module scope.)

        changed = unblock_ip(ip)
        try:
            log_attempt(
                username=session.get("username", "unknown"),
                ip=request.remote_addr or "unknown",
                success=bool(changed),
                suspicious=False,
                ai_prediction="ADMIN_UNBLOCK",
                threat_level="0",
            )
        except Exception:
            pass

        return redirect(url_for("dashboard") + "#blocked-ips")


