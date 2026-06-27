from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

try:
    from .config import RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_BLOCKED, RATE_LIMIT_BLOCK_MINUTES
    from .database import get_connection, _utc_now_iso
except ImportError:  # pragma: no cover
    from config import RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_BLOCKED, RATE_LIMIT_BLOCK_MINUTES
    from database import get_connection, _utc_now_iso


def now_iso() -> str:
    return _utc_now_iso()


def window_start_iso(now_iso_str: str, window_seconds: int = RATE_LIMIT_WINDOW_SECONDS) -> str:
    now_dt = datetime.fromisoformat(now_iso_str)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)
    since_dt = now_dt - timedelta(seconds=window_seconds)
    return since_dt.isoformat()


def ip_is_currently_blocked(ip: str, now_iso_str: str) -> bool:
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
            (ip, now_iso_str),
        )
        return cur.fetchone() is not None
    finally:
        conn.close()


def count_failed_attempts_last_window(ip: str, now_iso_str: str) -> int:
    since_iso = window_start_iso(now_iso_str, RATE_LIMIT_WINDOW_SECONDS)

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


def upsert_block_for_ip(
    *,
    ip: str,
    failed_attempts_in_window: int,
    threat_score: int,
    now_iso_str: str,
) -> None:
    blocked_until_dt = datetime.fromisoformat(now_iso_str)
    if blocked_until_dt.tzinfo is None:
        blocked_until_dt = blocked_until_dt.replace(tzinfo=timezone.utc)
    blocked_until_dt = blocked_until_dt + timedelta(minutes=RATE_LIMIT_BLOCK_MINUTES)
    blocked_until_iso = blocked_until_dt.isoformat()

    conn = get_connection()
    try:
        cur = conn.cursor()
        # SQLite UPSERT
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
            (ip, int(failed_attempts_in_window), int(threat_score), blocked_until_iso, now_iso_str),
        )
        conn.commit()
    finally:
        conn.close()


def fetch_blocked_ip_count(now_iso_str: str) -> int:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COUNT(*) as n
            FROM suspicious_ips
            WHERE blocked_until IS NOT NULL AND blocked_until > ?
            """,
            (now_iso_str,),
        )
        return int(cur.fetchone()["n"] or 0)
    finally:
        conn.close()


def fetch_currently_blocked_ips(now_iso_str: str, limit: int = 20) -> list[dict]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT ip, failed_attempts, threat_score, blocked_until, last_seen, blocked_count
            FROM suspicious_ips
            WHERE blocked_until IS NOT NULL AND blocked_until > ?
            ORDER BY threat_score DESC, failed_attempts DESC, blocked_count DESC
            LIMIT ?
            """,
            (now_iso_str, limit),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_top_blocked_ips(limit: int = 10) -> list[dict]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT ip, failed_attempts, threat_score, blocked_count, blocked_until, last_seen
            FROM suspicious_ips
            ORDER BY blocked_count DESC, threat_score DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def unblock_ip(ip: str) -> bool:
    """Manually unblock an IP by setting blocked_until = NULL.

    Returns True if a row was modified. ``blocked_count`` is a lifetime
    counter and is intentionally NOT decremented.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE suspicious_ips SET blocked_until = NULL WHERE ip = ?",
            (ip,),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()

