from __future__ import annotations

try:
    from .config import SUSPICIOUS_SCORE_THRESHOLD
    from .database import insert_threat_alert
    from .logger import log_threat
    from .detector import DetectionResult
except ImportError:  # pragma: no cover
    from config import SUSPICIOUS_SCORE_THRESHOLD
    from database import insert_threat_alert
    from logger import log_threat
    from detector import DetectionResult



def severity_from_score(score: float) -> int:
    """Map suspicion score to a severity level (1..5)."""
    if score >= 90:
        return 5
    if score >= 80:
        return 4
    if score >= 70:
        return 3
    if score >= 50:
        return 2
    return 1


def create_alert_for_detection(
    ip: str,
    detection: DetectionResult,
    extra_details: str = "",
) -> None:
    """Create and persist threat alert based on detection result."""

    # Stabilization: allow AI-driven alerts.
    # The pipeline may call this function when AI predicts risk even if
    # rule-based detection flags are false.
    ai_triggered = detection.suspicious is False and detection.brute_force is False and extra_details and (
        "ai_label=" in extra_details or "ai_score=" in extra_details
    )

    if not (detection.brute_force or detection.suspicious or ai_triggered):
        return

    if detection.brute_force:
        alert_type = "HONEYPOT_BRUTE_FORCE"
    elif detection.suspicious:
        alert_type = "SUSPICIOUS_ACTIVITY"
    else:
        # AI-only trigger: map to suspicious by default.
        alert_type = "SUSPICIOUS_ACTIVITY"


    severity = severity_from_score(detection.suspicious_score)

    details_parts = []
    if detection.reasons:
        details_parts.append("Reasons: " + " | ".join(detection.reasons))
    if extra_details:
        details_parts.append(extra_details)

    details = "\n".join(details_parts).strip() or f"Suspicion score={detection.suspicious_score:.1f}"

    insert_threat_alert(
        ip=ip,
        alert_type=alert_type,
        severity=severity,
        details=details,
    )
    log_threat(ip=ip, alert_type=alert_type, severity=severity, details=details)

