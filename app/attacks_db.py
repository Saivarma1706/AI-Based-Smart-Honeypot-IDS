"""app.attacks_db

Professional, modular SQLite database module for Smart Honeypot IDS.

Stores a unified attack history table with beginner-friendly, reusable
insert and fetch functions.

Required fields (per project request):
- username
- IP address
- login status
- threat level
- timestamp

Why this is modular:
- app/database.py in this repo already contains other tables.
- This module provides the specific *attacks* schema requested without
  breaking existing app code.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

try:
    from .config import DB_PATH
except ImportError:  # pragma: no cover
    from config import DB_PATH


@dataclass(frozen=True)
class AttackRecord:
    username: str
    ip: str
    login_status: str  # e.g. "SUCCESS" / "FAILED"
    threat_level: str  # e.g. "Safe" / "Suspicious" / "Threat"
    timestamp: str  # ISO8601


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection() -> sqlite3.Connection:
    """Create a SQLite connection and set row_factory."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_attacks_db() -> None:
    """Initialize dashboard-required legacy schema.

    NOTE:
    The simulator/security pipeline in this repo writes to:
      - login_attempts
      - threat_alerts

    Older versions of the dashboard used the `attacks` table.
    We keep this function for backward compatibility, but all
    dashboard metrics are now sourced from login_attempts/threat_alerts.
    """

    conn = get_connection()
    cur = conn.cursor()

    # Keep the legacy table to avoid breaking old deployments.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip TEXT NOT NULL,
            login_status TEXT NOT NULL,
            threat_level TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
        """
    )

    cur.execute("CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp);")

    conn.commit()
    conn.close()



def insert_attack(
    *,
    username: str,
    ip: str,
    login_status: str,
    threat_level: str,
    timestamp_iso: str | None = None,
) -> None:
    """Insert one attack record into the attacks table."""
    if timestamp_iso is None:
        timestamp_iso = _utc_now_iso()

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO attacks (username, ip, login_status, threat_level, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, ip, login_status, threat_level, timestamp_iso),
    )

    conn.commit()
    conn.close()


def fetch_recent_attacks(limit: int = 50) -> list[sqlite3.Row]:
    """Fetch recent dashboard rows.

    Dashboard template expects fields:
      - timestamp, username, ip, login_status, threat_level

    We map directly from `login_attempts` and `threat_alerts` since
    current pipeline does not populate the legacy `attacks` table.
    """

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
              created_at AS timestamp,
              username,
              ip,
              CASE WHEN success = 1 THEN 'SUCCESS' ELSE 'FAILED' END AS login_status,
              CASE
                WHEN EXISTS (
                  SELECT 1
                  FROM threat_alerts ta
                  WHERE ta.ip = la.ip
                    AND la.created_at >= datetime(ta.created_at, '-10 minutes')
                    AND la.created_at <= datetime(ta.created_at, '+10 minutes')
                    AND ta.severity = 5
                ) THEN 'Threat'
                WHEN EXISTS (
                  SELECT 1
                  FROM threat_alerts ta
                  WHERE ta.ip = la.ip
                    AND la.created_at >= datetime(ta.created_at, '-10 minutes')
                    AND la.created_at <= datetime(ta.created_at, '+10 minutes')
                    AND ta.severity IN (3,4)
                ) THEN 'Suspicious'
                ELSE 'Safe'
              END AS threat_level
            FROM login_attempts la
            ORDER BY la.id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        return list(rows)
    finally:
        conn.close()



def fetch_attacks_stats() -> dict[str, int]:
    """Return dashboard-friendly counts sourced from existing tables.

    The IDS pipeline writes:
      - login_attempts (per authentication attempt)
      - threat_alerts (per detection)

    The legacy `attacks` table is not populated by the current simulator.
    """

    conn = get_connection()
    try:
        cur = conn.cursor()

        # total attempts observed (login attempts)
        cur.execute("SELECT COUNT(*) as total FROM login_attempts")
        total = int(cur.fetchone()["total"] or 0)

        # suspicious_attempts approximated by rule/AI driven threat alerts.
        # Prefer threat_alerts severity to avoid relying on nonexistent attacks rows.
        cur.execute(
            "SELECT COUNT(*) as n FROM threat_alerts WHERE severity IN (3,4)"
        )
        suspicious = int(cur.fetchone()["n"] or 0)

        # threat_alerts: all threat alerts count
        cur.execute("SELECT COUNT(*) as n FROM threat_alerts")
        threat = int(cur.fetchone()["n"] or 0)

        conn.close()
        return {
            "total_attacks": total,
            "suspicious_attempts": suspicious,
            "threat_alerts": threat,
        }

    except Exception as e:
        import logging
        logging.error(f"Failed to fetch attack stats: {e}")
        return {
            "total_attacks": 0,
            "suspicious_attempts": 0,
            "threat_alerts": 0,
        }


def fetch_failed_login_count() -> int:
    """Count failed login attempts from login_attempts table."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as n FROM login_attempts WHERE success = 0")
        count = int(cur.fetchone()["n"])
        return count
    except Exception as e:
        import logging
        logging.error(f"Failed to fetch failed login count: {e}")
        return 0
    finally:
        conn.close()


def fetch_suspicious_ips() -> int:
    """Count unique IPs with multiple failed attempts (2+ failures)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(DISTINCT ip) as n
            FROM login_attempts
            WHERE success = 0
            GROUP BY ip
            HAVING COUNT(*) >= 2
        """)
        rows = cur.fetchall()
        count = len(rows)
        return count
    except Exception as e:
        import logging
        logging.error(f"Failed to fetch suspicious IPs: {e}")
        return 0
    finally:
        conn.close()


def fetch_threat_level_distribution() -> dict[str, int]:
    """Return distribution of threat levels (Safe/Suspicious/Threat).

    Dashboard expects keys: safe/suspicious/threat.

    Current schema does not include an explicit Safe/Suspicious/Threat label
    for every login_attempt. `threat_alerts` stores alerts with severity.

    Heuristic mapping used:
      - severity 1-2  => Safe
      - severity 3-4  => Suspicious
      - severity 5    => Threat
    """

    conn = get_connection()
    try:
        cur = conn.cursor()

        cur.execute(
            "SELECT COUNT(*) as n FROM threat_alerts WHERE severity IN (1,2)"
        )
        safe = int(cur.fetchone()["n"] or 0)

        cur.execute(
            "SELECT COUNT(*) as n FROM threat_alerts WHERE severity IN (3,4)"
        )
        suspicious = int(cur.fetchone()["n"] or 0)

        cur.execute("SELECT COUNT(*) as n FROM threat_alerts WHERE severity = 5")
        threat = int(cur.fetchone()["n"] or 0)

        return {
            "safe": safe,
            "suspicious": suspicious,
            "threat": threat,
        }

    except Exception as e:
        import logging
        logging.error(f"Failed to fetch threat distribution: {e}")
        return {"safe": 0, "suspicious": 0, "threat": 0}
    finally:
        conn.close()


def fetch_top_attacking_ips(limit: int = 10) -> list[dict]:
    """Fetch top attacking IPs with attempt counts."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT ip, COUNT(*) as attempt_count,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_count
            FROM login_attempts
            GROUP BY ip
            ORDER BY attempt_count DESC
            LIMIT ?
        """, (limit,))

        rows = cur.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        import logging
        logging.error(f"Failed to fetch top attacking IPs: {e}")
        return []
    finally:
        conn.close()


def fetch_threat_alert_count_by_severity() -> dict[str, int]:
    """Count threat alerts grouped by severity level."""
    conn = get_connection()
    try:
        cur = conn.cursor()

        distribution = {}
        for severity in range(1, 6):
            cur.execute(
                "SELECT COUNT(*) as n FROM threat_alerts WHERE severity = ?",
                (severity,)
            )
            count = int(cur.fetchone()["n"])
            distribution[f"severity_{severity}"] = count

        return distribution
    except Exception as e:
        import logging
        logging.error(f"Failed to fetch threat alert distribution: {e}")
        return {}
    finally:
        conn.close()


def fetch_service_activity_distribution(limit: int = 6) -> list[dict]:
    """Return total attempts grouped by service_route.

    Primary source of truth: login_attempts.service_route.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT service_route, COUNT(*) as attempt_count
            FROM login_attempts
            WHERE service_route IS NOT NULL
            GROUP BY service_route
            ORDER BY attempt_count DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        import logging
        logging.error(f"Failed to fetch service activity distribution: {e}")
        return []
    finally:
        conn.close()


def fetch_failed_attempts_by_service(limit: int = 6) -> list[dict]:
    """Return failed attempts grouped by service_route."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT service_route, COUNT(*) as failed_count
            FROM login_attempts
            WHERE success = 0 AND service_route IS NOT NULL
            GROUP BY service_route
            ORDER BY failed_count DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        import logging
        logging.error(f"Failed to fetch failed attempts by service: {e}")
        return []
    finally:
        conn.close()


def fetch_top_attacked_services(limit: int = 5) -> list[dict]:
    """Return top attacked services.

    Defined as services with the highest number of failed attempts.
    """
    return fetch_failed_attempts_by_service(limit=limit)


def fetch_threat_counts_by_service(limit: int = 6) -> list[dict]:
    """Return threat counts by service.

    Note: threat_alerts does not store service_route in the current schema.
    We approximate by joining threat_alerts -> login_attempts on IP and
    counting login_attempts whose created_at is within ±10 minutes of the
    threat alert's created_at.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT la.service_route, COUNT(*) as threat_count
            FROM threat_alerts ta
            JOIN login_attempts la
              ON la.ip = ta.ip
            WHERE la.service_route IS NOT NULL
              AND la.created_at >= datetime(ta.created_at, '-10 minutes')
              AND la.created_at <= datetime(ta.created_at, '+10 minutes')
            GROUP BY la.service_route
            ORDER BY threat_count DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        import logging
        logging.error(f"Failed to fetch threat counts by service: {e}")
        return []
    finally:
        conn.close()



def fetch_hourly_attempt_volume(hours: int = 24) -> list[dict]:
    """Return [(hour_iso, attempts, failed), ...] for the last N hours.

    Phase 6 Task 2 (Tier A). Pure read of login_attempts.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT strftime('%Y-%m-%d %H:00', created_at) AS hour,
                   COUNT(*) AS attempts,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed
            FROM login_attempts
            WHERE created_at >= datetime('now', ?)
            GROUP BY hour
            ORDER BY hour
            """,
            (f"-{hours} hours",),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_top_targeted_usernames(limit: int = 10) -> list[dict]:
    """Return top usernames by attempt count.

    Phase 6 Task 2 (Tier A). Pure read of login_attempts.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT username,
                   COUNT(*) AS attempts,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed
            FROM login_attempts
            GROUP BY username
            ORDER BY attempts DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_failure_reason_distribution(limit: int = 10) -> list[dict]:
    """Return counts grouped by failure_reason (NULL = successful login).

    Phase 6 Task 2 (Tier A). Pure read of login_attempts.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COALESCE(failure_reason, '(success)') AS reason,
                   COUNT(*) AS n
            FROM login_attempts
            GROUP BY reason
            ORDER BY n DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_ip_summary(ip: str) -> dict:
    """Return aggregate counts and timestamps for one IP from login_attempts.

    Phase 6 Task 4. Pure read.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS success_count,
                MIN(created_at) AS first_seen,
                MAX(created_at) AS last_seen
            FROM login_attempts
            WHERE ip = ?
            """,
            (ip,),
        )
        row = cur.fetchone()
        return {
            "ip": ip,
            "total": int(row["total"] or 0) if row else 0,
            "failed": int(row["failed"] or 0) if row else 0,
            "success_count": int(row["success_count"] or 0) if row else 0,
            "first_seen": row["first_seen"] if row else None,
            "last_seen": row["last_seen"] if row else None,
        }
    finally:
        conn.close()


def fetch_ip_block_record(ip: str) -> dict | None:
    """Return the suspicious_ips row for one IP, or None.

    Phase 6 Task 4. Pure read.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT ip, failed_attempts, threat_score,
                   blocked_until, last_seen, blocked_count
            FROM suspicious_ips
            WHERE ip = ?
            """,
            (ip,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def fetch_ip_services_targeted(ip: str) -> list[dict]:
    """Group login_attempts by service_route for one IP.

    Phase 6 Task 4. Pure read.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT service_route,
                   COUNT(*) AS attempts,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed
            FROM login_attempts
            WHERE ip = ? AND service_route IS NOT NULL
            GROUP BY service_route
            ORDER BY attempts DESC
            """,
            (ip,),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_ip_usernames_targeted(ip: str) -> list[dict]:
    """Group login_attempts by username for one IP.

    Phase 6 Task 4. Pure read.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT username,
                   COUNT(*) AS attempts,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed
            FROM login_attempts
            WHERE ip = ?
            GROUP BY username
            ORDER BY attempts DESC
            """,
            (ip,),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_ip_failure_reasons(ip: str) -> list[dict]:
    """Group login_attempts by failure_reason for one IP.

    Phase 6 Task 4. Pure read.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COALESCE(failure_reason, '(success)') AS reason,
                   COUNT(*) AS n
            FROM login_attempts
            WHERE ip = ?
            GROUP BY reason
            ORDER BY n DESC
            """,
            (ip,),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_ip_threat_alerts(ip: str, limit: int = 50) -> list[dict]:
    """Return threat_alerts rows for one IP, newest first.

    Phase 6 Task 4. Pure read.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, created_at, alert_type, severity, details
            FROM threat_alerts
            WHERE ip = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (ip, limit),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_ip_recent_activity(ip: str, limit: int = 50) -> list[dict]:
    """Return recent login_attempts rows for one IP, newest first.

    Phase 6 Task 4. Pure read.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, created_at, username, success, failure_reason,
                   service_route, event_type
            FROM login_attempts
            WHERE ip = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (ip, limit),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def bulk_insert_attacks(records: Iterable[AttackRecord]) -> None:
    """Optional helper: insert many records efficiently."""
    rows = list(records)
    if not rows:
        return

    conn = get_connection()
    cur = conn.cursor()

    cur.executemany(
        """
        INSERT INTO attacks (username, ip, login_status, threat_level, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (r.username, r.ip, r.login_status, r.threat_level, r.timestamp)
            for r in rows
        ],
    )

    conn.commit()
    conn.close()

