from __future__ import annotations

from datetime import datetime, timedelta, timezone


def now_utc() -> datetime:
    """Current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


def utc_iso(dt: datetime) -> str:
    """Convert a datetime to ISO-8601 string."""
    return dt.isoformat()


def ip_normalize(ip: str | None) -> str:
    """Normalize IP for logging/storage.

    In production behind a proxy you would use ProxyFix and trust headers.
    For this project we keep it simple.
    """
    if not ip:
        return "unknown"
    return ip.strip()


def _parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _average_login_speed_seconds(attempts_recent: list[dict]) -> float:
    timestamps = [
        _parse_iso_timestamp(a.get("created_at"))
        for a in attempts_recent
        if a.get("created_at")
    ]
    timestamps = [t for t in timestamps if t is not None]
    if len(timestamps) < 2:
        return 0.0

    timestamps.sort()
    intervals = [
        (timestamps[i] - timestamps[i - 1]).total_seconds()
        for i in range(1, len(timestamps))
    ]
    return float(max(0.0, sum(intervals) / len(intervals)))


def build_features(attempts_recent: list[dict]) -> dict:
    """Build runtime features that match the trained AI model.

    The model expects exactly these fields:
    - failed_attempts
    - login_speed
    - repeated_ips
    - suspicious_behavior_score
    """
    failed_attempts = sum(1 for a in attempts_recent if a.get("success") == 0)
    consecutive_failures = 0
    for a in attempts_recent:
        if a.get("success") == 0:
            consecutive_failures += 1
        else:
            break

    repeated_ips = max(
        0,
        len({a.get("ip") for a in attempts_recent if a.get("ip")}) - 1,
    )
    login_speed = _average_login_speed_seconds(attempts_recent)

    failure_rate = (
        float(failed_attempts) / len(attempts_recent)
        if attempts_recent
        else 0.0
    )

    suspicious_behavior_score = float(
        min(
            100.0,
            failed_attempts * 8.0
            + consecutive_failures * 5.0
            + failure_rate * 40.0,
        )
    )

    return {
        "failed_attempts": float(failed_attempts),
        "login_speed": float(login_speed),
        "repeated_ips": float(repeated_ips),
        "suspicious_behavior_score": float(suspicious_behavior_score),
    }


def minutes_to_seconds(minutes: float) -> int:
    return int(minutes * 60)

