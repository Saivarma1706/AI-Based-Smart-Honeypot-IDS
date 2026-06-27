import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone


try:
    from .config import DB_PATH
except ImportError:  # pragma: no cover
    from config import DB_PATH


def _utc_now_iso() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def get_connection() -> sqlite3.Connection:
    """Create a SQLite connection.

    `check_same_thread=False` makes local development with Flask safer.
    `timeout=5.0` prevents indefinite hangs on Windows file-lock contention.

    The parent directory is created lazily so that a read-only runtime
    install (e.g. a PyInstaller build under Program Files\\) surfaces a
    clear PermissionError at the first DB call instead of crashing the
    whole process at import time.
    """
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        try:
            os.makedirs(db_dir, exist_ok=True)
        except (OSError, PermissionError):
            logging.error(f"Cannot create DB directory: {db_dir}")
            raise
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize required tables."""
    conn = get_connection()
    try:
        cur = conn.cursor()

        # login_attempts is the main source for per-IP detection.
        # We extend it with optional metadata columns for multi-service monitoring.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                success INTEGER NOT NULL,
                failure_reason TEXT,
                is_honeypot_target INTEGER NOT NULL DEFAULT 1,
                service_route TEXT,
                request_path TEXT,
                event_type TEXT
            );
            """
        )

        # Safe schema evolution: if an older DB exists without the new columns,
        # ALTER TABLE adds them (SQLite will ignore duplicates).

        try:
            cur.execute("ALTER TABLE login_attempts ADD COLUMN service_route TEXT;")
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE login_attempts ADD COLUMN request_path TEXT;")
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE login_attempts ADD COLUMN event_type TEXT;")
        except Exception:
            pass

        # Rate limiting / temporary IP blocking state
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS suspicious_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                threat_score INTEGER NOT NULL DEFAULT 0,
                blocked_until TEXT,
                last_seen TEXT NOT NULL,
                blocked_count INTEGER NOT NULL DEFAULT 0
            );
            """
        )

        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_suspicious_ips_blocked_until ON suspicious_ips(blocked_until);"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_suspicious_ips_last_seen ON suspicious_ips(last_seen);"
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                ip TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity INTEGER NOT NULL,
                details TEXT
            );
            """
        )

        conn.commit()
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


def insert_login_attempt(
    ip: str,
    username: str,
    success: bool,
    failure_reason: str | None,
    service_route: str | None = None,
    request_path: str | None = None,
    event_type: str | None = None,
) -> None:
    """Insert a login attempt record.

    Args:
        ip: Client IP address
        username: Username attempted
        success: Whether authentication succeeded
        failure_reason: Reason for failure (if any)
        service_route: Fake service route that was targeted (e.g., /ssh)
        request_path: Full request path (e.g., /ssh)
        event_type: Short string describing the event (e.g., SSH_AUTH)
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO login_attempts (
                created_at, ip, username, success, failure_reason,
                service_route, request_path, event_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _utc_now_iso(),
                ip,
                username,
                int(success),
                failure_reason,
                service_route,
                request_path,
                event_type,
            ),
        )
        conn.commit()

    except Exception as e:
        logging.error(f"Failed to insert login attempt for ip={ip}, username={username}: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


def is_ip_currently_blocked(ip: str, now_iso: str) -> bool:
    """Return True if `ip` is currently blocked until a future time."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT 1
            FROM suspicious_ips
            WHERE ip = ?
              AND blocked_until IS NOT NULL
              AND blocked_until > ?
            LIMIT 1
            """,
            (ip, now_iso),
        )
        return cur.fetchone() is not None
    finally:
        conn.close()


def count_failed_attempts_last_window(ip: str, now_iso: str, window_seconds: int) -> int:
    """Count failed attempts for `ip` in the last `window_seconds` window."""
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)
    since_dt = now_dt - timedelta(seconds=window_seconds)
    since_iso = since_dt.isoformat()

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COUNT(*) as n
            FROM login_attempts
            WHERE ip = ?
              AND success = 0
              AND created_at >= ?
            """,
            (ip, since_iso),
        )
        return int(cur.fetchone()["n"] or 0)
    finally:
        conn.close()


def upsert_suspicious_ip_block(
    *,
    ip: str,
    failed_attempts_in_window: int,
    threat_score: int,
    now_iso: str,
    blocked_minutes: int,
) -> None:
    """Update `suspicious_ips` and increment `blocked_count` when blocking."""
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)
    blocked_until_dt = now_dt + timedelta(minutes=blocked_minutes)
    blocked_until_iso = blocked_until_dt.isoformat()

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO suspicious_ips (
                ip, failed_attempts, threat_score, blocked_until, last_seen, blocked_count
            )
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(ip) DO UPDATE SET
                failed_attempts = excluded.failed_attempts,
                threat_score = excluded.threat_score,
                blocked_until = excluded.blocked_until,
                last_seen = excluded.last_seen,
                blocked_count = suspicious_ips.blocked_count + 1
            """,
            (ip, int(failed_attempts_in_window), int(threat_score), blocked_until_iso, now_iso),
        )
        conn.commit()
    finally:
        conn.close()


def fetch_recent_attempts_by_ip(ip: str, since_timestamp_iso: str, limit: int = 200) -> list[sqlite3.Row]:
    """Fetch recent login attempts for an IP within a time window.

    Args:
        ip: IP address to query
        since_timestamp_iso: ISO-8601 timestamp (inclusive)
        limit: Maximum number of records to return

    Returns:
        List of sqlite3.Row objects (dict-like)
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT *
            FROM login_attempts
            WHERE ip = ? AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (ip, since_timestamp_iso, limit),
        )
        rows = cur.fetchall()
        return list(rows)
    except Exception as e:
        logging.error(f"Failed to fetch recent attempts for ip={ip}: {e}")
        return []
    finally:
        conn.close()


def insert_threat_alert(ip: str, alert_type: str, severity: int, details: str) -> None:
    """Insert a threat alert record.


    Args:
        ip: Attacker IP address
        alert_type: Type of alert (e.g., "HONEYPOT_BRUTE_FORCE", "SUSPICIOUS_ACTIVITY")
        severity: Severity level (1-5)
        details: Additional details about the threat
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO threat_alerts (created_at, ip, alert_type, severity, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (_utc_now_iso(), ip, alert_type, int(severity), details),
        )
        conn.commit()
    except Exception as e:
        logging.error(f"Failed to insert threat alert for ip={ip}, type={alert_type}: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()
