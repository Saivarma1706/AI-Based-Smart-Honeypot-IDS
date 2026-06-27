from __future__ import annotations

"""Shared security monitoring pipeline.

This module centralizes the cybersecurity event processing logic so that all
fake services (SSH / database / server / API auth) reuse the same flow.

The centralized function:
- captures IP
- stores login attempt + service metadata
- runs rule-based detector + AI prediction
- triggers threat alerts

Beginner-friendly overview:
When a request is submitted to a fake service, we treat it like a
"login attempt" event and feed recent history for that IP into the existing
detector + AI model.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from .config import BRUTE_FORCE_WINDOW_SECONDS, RECENT_ATTEMPTS_LIMIT, RATE_LIMIT_FAILS_THRESHOLD
    from .database import (
        fetch_recent_attempts_by_ip,
        insert_login_attempt,
    )
    from .detector import evaluate_suspicion
    from .ai_model import ai_predict_label_and_score
    from .alerts import create_alert_for_detection
    from .rate_limit_db import (
        ip_is_currently_blocked,
        count_failed_attempts_last_window,
        upsert_block_for_ip,
        now_iso,
    )
    from .utils import build_features, ip_normalize
except ImportError:  # pragma: no cover
    from config import BRUTE_FORCE_WINDOW_SECONDS, RECENT_ATTEMPTS_LIMIT, RATE_LIMIT_FAILS_THRESHOLD
    from database import fetch_recent_attempts_by_ip, insert_login_attempt
    from detector import evaluate_suspicion
    from ai_model import ai_predict_label_and_score
    from alerts import create_alert_for_detection
    from rate_limit_db import (
        ip_is_currently_blocked,
        count_failed_attempts_last_window,
        upsert_block_for_ip,
        now_iso,
    )
    from utils import build_features, ip_normalize



@dataclass(frozen=True)
class SecurityEventResult:
    success: bool
    brute_force: bool
    suspicious: bool
    ai_label: str
    ai_score: float
    blocked: bool = False



def process_security_event(
    *,
    raw_ip: str | None,
    username: str,
    password: str,
    success: bool,
    failure_reason: str | None,
    service_route: str,
    request_path: str,
    event_type: str,
) -> SecurityEventResult:
    """Process one simulated authentication event.

    All services should call this instead of duplicating IDS logic.
    """

    ip = ip_normalize(raw_ip)

    # ---- Phase 5 Task 1: Rate limiting / temporary IP blocking ----
    # If currently blocked, record the attempt as a failed rate-limit event.
    # (rate_limit_db imports live at module scope above, alongside the
    # other dual-imports, so this works in both dev and PyInstaller modes.)
    now_iso_str = now_iso()

    if ip_is_currently_blocked(ip, now_iso_str):
        insert_login_attempt(
            ip=ip,
            username=username,
            success=False,
            failure_reason="RATE_LIMIT_BLOCKED",
            service_route=service_route,
            request_path=request_path,
            event_type="RATE_LIMIT_BLOCK",
        )
        return SecurityEventResult(
            success=False,
            brute_force=False,
            suspicious=False,
            ai_label="RateLimitBlocked",
            ai_score=0.0,
            blocked=True,
        )

    # Persist attempt with service metadata.
    insert_login_attempt(
        ip=ip,
        username=username,
        success=success,
        failure_reason=failure_reason,
        service_route=service_route,
        request_path=request_path,
        event_type=event_type,
    )

    # Detector + AI analysis uses recent attempts for this IP.
    since = datetime.now(timezone.utc) - timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)
    attempts_recent = fetch_recent_attempts_by_ip(
        ip=ip,
        since_timestamp_iso=since.isoformat(),
        limit=RECENT_ATTEMPTS_LIMIT,
    )

    attempts_recent_dicts = [dict(r) for r in attempts_recent]
    detection = evaluate_suspicion(attempts_recent_dicts)

    features = build_features(attempts_recent_dicts)
    ai_result = ai_predict_label_and_score(features)

    if detection.brute_force or detection.suspicious or ai_result.predicted_label != "Safe":
        extra = (
            f"service={service_route} ai_label={ai_result.predicted_label} "
            f"ai_score={ai_result.threat_score:.1f} suspicion_score={detection.suspicious_score:.1f}"
        )
        create_alert_for_detection(ip=ip, detection=detection, extra_details=extra)

    # If this attempt was a failure, evaluate rate limit threshold.
    if not success:
        failed_attempts_in_window = count_failed_attempts_last_window(ip, now_iso_str)
        if failed_attempts_in_window >= int(RATE_LIMIT_FAILS_THRESHOLD):

            # Threat score for the block record: use AI score if available.
            upsert_block_for_ip(
                ip=ip,
                failed_attempts_in_window=failed_attempts_in_window,
                threat_score=int(ai_result.threat_score),
                now_iso_str=now_iso_str,
            )

            # Record the act of blocking into login_attempts as required.
            insert_login_attempt(
                ip=ip,
                username=username,
                success=False,
                failure_reason="RATE_LIMIT_BLOCKED",
                service_route=service_route,
                request_path=request_path,
                event_type="RATE_LIMIT_BLOCK",
            )

            # Generate a threat alert when the threshold is exceeded.
            # We will always create an alert for the rate-limit block using the existing alert pipeline.
            # Use current detection output plus extra details to ensure gating triggers.
            extra = (
                f"service={service_route} ai_label={ai_result.predicted_label} "
                f"ai_score={ai_result.threat_score:.1f} rate_limit_failed_attempts={failed_attempts_in_window}"
            )
            create_alert_for_detection(ip=ip, detection=detection, extra_details=extra)


            # Mark blocked in return.
            return SecurityEventResult(
                success=False,
                brute_force=detection.brute_force,
                suspicious=True,
                ai_label=ai_result.predicted_label,
                ai_score=ai_result.threat_score,
                blocked=True,
            )

    return SecurityEventResult(
        success=success,
        brute_force=detection.brute_force,
        suspicious=detection.suspicious,
        ai_label=ai_result.predicted_label,
        ai_score=ai_result.threat_score,
        blocked=False,
    )


