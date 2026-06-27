"""app.exports

Phase 6 Task 3 (reduced scope): CSV + PDF export helpers.

- Three full-dump fetch helpers (login_attempts, threat_alerts, suspicious_ips)
- A CSV streaming response builder
- A multi-section PDF report builder (uses reportlab)

Reuses the existing fetch_* helpers from app/attacks_db and app.rate_limit_db.
No schema changes; no new tables; no writes.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Iterable, Sequence

try:
    from .attacks_db import get_connection
    from .attacks_db import (
        fetch_recent_attacks,
        fetch_attacks_stats,
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
    )
    from .rate_limit_db import (
        fetch_blocked_ip_count,
        fetch_currently_blocked_ips,
        now_iso,
    )
except ImportError:  # pragma: no cover
    from attacks_db import (
        get_connection,
        fetch_recent_attacks,
        fetch_attacks_stats,
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
    )
    from rate_limit_db import (
        fetch_blocked_ip_count,
        fetch_currently_blocked_ips,
        now_iso,
    )


# ---------------------------------------------------------------------------
# Full-dump fetch helpers
# ---------------------------------------------------------------------------

def fetch_all_login_attempts(limit: int = 10000, offset: int = 0) -> list[dict]:
    """Return all login_attempts rows (paginated). Read-only."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, created_at, ip, username, success, failure_reason,
                   is_honeypot_target, service_route, request_path, event_type
            FROM login_attempts
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_all_threat_alerts(limit: int = 10000, offset: int = 0) -> list[dict]:
    """Return all threat_alerts rows (paginated). Read-only."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, created_at, ip, alert_type, severity, details
            FROM threat_alerts
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_all_suspicious_ips(limit: int = 10000, offset: int = 0) -> list[dict]:
    """Return all suspicious_ips rows (paginated). Read-only."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, ip, failed_attempts, threat_score,
                   blocked_until, last_seen, blocked_count
            FROM suspicious_ips
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CSV streaming response
# ---------------------------------------------------------------------------

def stream_csv_response(headers: Sequence[str], rows: Iterable[Sequence],
                        filename: str):
    """Build a Flask Response containing a CSV body with attachment headers.

    Uses the Python standard library csv module (no new dependency).
    """
    from flask import Response

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(list(headers))
    for r in rows:
        writer.writerow(list(r))
    return Response(
        buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# PDF report builder
# ---------------------------------------------------------------------------

def build_security_report_pdf() -> bytes:
    """Build a multi-section security report PDF.

    Layout:
      Title page (Smart Honeypot IDS - Security Report, timestamp)
      1. Headline metrics
      2. Threat distribution
      3. Top 10 attacking IPs
      4. Top 10 targeted usernames
      5. Failure reasons
      6. Currently blocked IPs
      7. Recent attack activity (last 25)

    Uses reportlab's canvas API; all data is fetched live via the
    existing fetch_* helpers.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4

    def draw_line(y: float, text: str, size: int = 11, bold: bool = False) -> float:
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(50, y, text)
        return y - (size + 4)

    # ---- Title page ----
    now_str = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _now = now_iso()
    y = height - 60
    y = draw_line(y, "Smart Honeypot IDS - Security Report", 18, bold=True)
    y = draw_line(y, f"Generated: {now_str} UTC", 9)

    # ---- 1. Headline metrics ----
    stats = fetch_attacks_stats()
    n_failed = fetch_failed_login_count()
    n_susp = fetch_suspicious_ips()
    n_blocked = fetch_blocked_ip_count(_now)
    sev = fetch_threat_alert_count_by_severity() or {}
    y -= 16
    y = draw_line(y, "1. Headline metrics", 13, bold=True)
    y = draw_line(y, f"Total attempts:  {stats.get('total_attacks', 0)}")
    y = draw_line(y, f"Failed logins:   {n_failed}")
    y = draw_line(y, f"Threat alerts:   {stats.get('threat_alerts', 0)}")
    y = draw_line(y, f"Suspicious IPs:  {n_susp}")
    y = draw_line(y, f"Blocked IPs:     {n_blocked}")
    y = draw_line(
        y,
        "Alert severity: "
        + " ".join(f"s{level}={sev.get(f'severity_{level}', 0)}" for level in range(1, 6)),
    )
    y -= 8

    # ---- 2. Threat distribution ----
    dist = fetch_threat_level_distribution()
    y = draw_line(y, "2. Threat distribution", 13, bold=True)
    y = draw_line(
        y,
        f"Safe: {dist.get('safe', 0)}   "
        f"Suspicious: {dist.get('suspicious', 0)}   "
        f"Threat: {dist.get('threat', 0)}",
    )
    y -= 8

    c.showPage()

    # ---- Helper: render a table on its own page ----
    def render_table_page(title: str, columns: Sequence[str],
                          rows: Sequence[Sequence]) -> None:
        nonlocal y
        c.setFont("Helvetica-Bold", 13)
        c.drawString(50, height - 60, title)
        col_w = (width - 100) / max(len(columns), 1)
        y = height - 90
        c.setFont("Helvetica-Bold", 9)
        x = 50
        for col in columns:
            c.drawString(x, y, col)
            x += col_w
        y -= 14
        c.setFont("Helvetica", 9)
        for r in rows:
            x = 50
            for v in r:
                txt = "" if v is None else str(v)
                if len(txt) > 38:
                    txt = txt[:35] + "..."
                c.drawString(x, y, txt)
                x += col_w
            y -= 12
            if y < 60:
                c.showPage()
                c.setFont("Helvetica-Bold", 13)
                c.drawString(50, height - 60, title + " (cont.)")
                col_w = (width - 100) / max(len(columns), 1)
                y = height - 90
                c.setFont("Helvetica-Bold", 9)
                x = 50
                for col in columns:
                    c.drawString(x, y, col)
                    x += col_w
                y -= 14
                c.setFont("Helvetica", 9)
        c.showPage()

    # ---- 3. Top 10 attacking IPs ----
    render_table_page(
        "3. Top 10 Attacking IPs",
        ["IP", "Attempts", "Failed"],
        [
            (r["ip"], r["attempt_count"], r["failed_count"])
            for r in fetch_top_attacking_ips(limit=10)
        ],
    )

    # ---- 4. Top 10 targeted usernames ----
    render_table_page(
        "4. Top 10 Targeted Usernames",
        ["Username", "Attempts", "Failed"],
        [
            (r["username"], r["attempts"], r["failed"])
            for r in fetch_top_targeted_usernames(limit=10)
        ],
    )

    # ---- 5. Failure reasons ----
    render_table_page(
        "5. Failure Reasons",
        ["Reason", "Count"],
        [
            (r["reason"], r["n"])
            for r in fetch_failure_reason_distribution(limit=20)
        ],
    )

    # ---- 6. Currently blocked IPs ----
    render_table_page(
        "6. Currently Blocked IPs",
        ["IP", "FA", "TS", "Blocked Until", "#"],
        [
            (
                r["ip"],
                r["failed_attempts"],
                r["threat_score"],
                (r["blocked_until"] or "-")[-19:] if r["blocked_until"] else "-",
                r["blocked_count"],
            )
            for r in fetch_currently_blocked_ips(_now, limit=100)
        ],
    )

    # ---- 7. Recent attack activity ----
    render_table_page(
        "7. Recent Attack Activity (last 25)",
        ["Timestamp", "Username", "IP", "Status", "Threat"],
        [
            (
                (r["timestamp"] or "-")[:19],
                r["username"],
                r["ip"],
                r["login_status"],
                r["threat_level"],
            )
            for r in fetch_recent_attacks(limit=25)
        ],
    )

    c.save()
    return buf.getvalue()
