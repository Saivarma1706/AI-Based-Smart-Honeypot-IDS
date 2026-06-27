from __future__ import annotations

from dataclasses import dataclass

try:
    from .config import (
        BRUTE_FORCE_FAILS_THRESHOLD,
        BRUTE_FORCE_WINDOW_SECONDS,
        SUSPICIOUS_SCORE_THRESHOLD,
    )
    from .utils import build_features
except ImportError:  # pragma: no cover
    from config import (
        BRUTE_FORCE_FAILS_THRESHOLD,
        BRUTE_FORCE_WINDOW_SECONDS,
        SUSPICIOUS_SCORE_THRESHOLD,
    )
    from utils import build_features



@dataclass
class DetectionResult:
    brute_force: bool
    suspicious_score: float
    suspicious: bool
    reasons: list[str]


def evaluate_suspicion(attempts_recent: list[dict]) -> DetectionResult:
    """Evaluate rule-based and simple heuristic suspicion.

    - Brute-force: too many failures in a short window.
    - Suspicious score: based on failure concentration.

    The same attempts are also compatible with the AI feature builder.
    """

    if not attempts_recent:
        return DetectionResult(
            brute_force=False,
            suspicious_score=0.0,
            suspicious=False,
            reasons=[],
        )

    features = build_features(attempts_recent)
    failures = int(features["failed_attempts"])
    total = len(attempts_recent)
    failure_rate = failures / total if total else 0.0

    brute_force = failures >= BRUTE_FORCE_FAILS_THRESHOLD

    consecutive_failures = 0
    for a in attempts_recent:
        if a.get("success") == 0:
            consecutive_failures += 1
        else:
            break

    suspicious_score = 0.0
    suspicious_score += min(40.0, consecutive_failures * 5.0)
    suspicious_score += min(50.0, failure_rate * 100.0)

    reasons: list[str] = []
    if brute_force:
        reasons.append(
            f"Brute-force pattern: {failures} failed attempts within {BRUTE_FORCE_WINDOW_SECONDS}s (threshold {BRUTE_FORCE_FAILS_THRESHOLD})."
        )
    if failure_rate >= 0.6:
        reasons.append(f"High failure concentration: failure rate {failure_rate:.2f}.")
    if consecutive_failures >= 5:
        reasons.append(f"Many consecutive failures: {consecutive_failures}.")

    suspicious = suspicious_score >= SUSPICIOUS_SCORE_THRESHOLD

    if brute_force:
        suspicious = True
        suspicious_score = max(suspicious_score, SUSPICIOUS_SCORE_THRESHOLD)

    suspicious_score = float(max(0.0, min(100.0, suspicious_score)))

    return DetectionResult(
        brute_force=brute_force,
        suspicious_score=suspicious_score,
        suspicious=suspicious,
        reasons=reasons,
    )

