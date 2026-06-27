from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


# We intentionally keep imports lightweight so this module can run early
# during startup (before Flask is initialized).


@dataclass(frozen=True)
class IntegrityVerificationResult:
    passed: bool
    mismatches: dict[str, dict[str, str]]  # file -> {expected, actual}
    missing: list[str]
    manifest_path: str


def _project_root() -> str:
    """Return Smart_Honeypot_IDS project root."""
    # app/ -> project root
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def calculate_sha256(file_path: str) -> str:
    """Calculate SHA-256 hex digest for a given file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_rel_path_to_abs(rel_path: str) -> str:
    return os.path.join(_project_root(), rel_path.replace("/", os.sep))


def generate_manifest() -> dict[str, Any]:
    """Generate an integrity manifest dictionary.

    The manifest is intended to be persisted as integrity_manifest.json.
    """

    files_to_hash = {
        "app/main.py",
        "app/security_pipeline.py",
        "app/ai_model.py",
        "models/anomaly_model.joblib",
    }

    manifest_files: dict[str, str] = {}
    for rel in sorted(files_to_hash):
        abs_path = _manifest_rel_path_to_abs(rel)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Integrity manifest cannot be generated; missing: {rel} ({abs_path})")
        manifest_files[rel.replace("\\", "/")] = calculate_sha256(abs_path)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": manifest_files,
    }


def _load_manifest(manifest_path: str) -> dict[str, Any]:
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)


def verify_integrity() -> IntegrityVerificationResult:
    """Verify required files against integrity_manifest.json.

    Returns a structured result. Does not raise.
    """

    manifest_path = os.path.join(_project_root(), "integrity_manifest.json")
    manifest: dict[str, Any] = _load_manifest(manifest_path)

    files_expected: dict[str, str] = manifest.get("files", {})

    required_files = [
        "app/main.py",
        "app/security_pipeline.py",
        "app/ai_model.py",
        "models/anomaly_model.joblib",
    ]

    mismatches: dict[str, dict[str, str]] = {}
    missing: list[str] = []

    for rel in required_files:
        rel_norm = rel.replace("\\", "/")
        expected = files_expected.get(rel_norm)
        abs_path = _manifest_rel_path_to_abs(rel)

        if expected is None:
            # Manifest doesn't define this required file.
            missing.append(rel_norm)
            continue

        if not os.path.exists(abs_path):
            missing.append(rel_norm)
            continue

        actual = calculate_sha256(abs_path)
        if actual != expected:
            mismatches[rel_norm] = {"expected": expected, "actual": actual}

    passed = not mismatches and not missing
    return IntegrityVerificationResult(
        passed=passed,
        mismatches=mismatches,
        missing=missing,
        manifest_path=manifest_path,
    )


def _create_integrity_alert_and_log(result: IntegrityVerificationResult) -> None:
    """Create a security alert and log incident using existing infrastructure."""

    # Lazy imports (only on failure) to avoid startup-time import risk.
    try:
        from .alerts import create_alert_for_detection  # type: ignore
        from .detector import DetectionResult  # type: ignore
        from .logger import log_threat  # type: ignore
        from .database import insert_threat_alert  # type: ignore
    except Exception:
        create_alert_for_detection = None  # type: ignore
        DetectionResult = None  # type: ignore
        log_threat = None  # type: ignore
        insert_threat_alert = None  # type: ignore

    details = {
        "passed": result.passed,
        "missing": result.missing,
        "mismatches": result.mismatches,
        "manifest_path": result.manifest_path,
    }

    # Use logger.log_threat if available.
    if log_threat is not None:
        try:
            log_threat(
                ip="server-startup",
                alert_type="INTEGRITY_VERIFICATION_FAILED",
                severity=5,
                details=json.dumps(details, ensure_ascii=False),
            )
        except Exception:
            pass

    # Persist alert via DB if possible.
    if insert_threat_alert is not None:
        try:
            # severity (1..5). This is a critical security event.
            insert_threat_alert(
                ip="server-startup",
                alert_type="INTEGRITY_VERIFICATION_FAILED",
                severity=5,
                details=json.dumps(details, ensure_ascii=False),
            )
        except Exception:
            pass

    # Additionally, if create_alert_for_detection is available, we can attempt
    # to record via that pipeline, but it's not guaranteed to accept our fake
    # DetectionResult. We keep this best-effort and never block on it.
    if create_alert_for_detection is not None and DetectionResult is not None:
        try:
            det = DetectionResult(
                brute_force=False,
                suspicious=True,
                suspicious_score=100.0,
                reasons=["integrity_manifest mismatch"],
                ai_score=100.0,
            )
            create_alert_for_detection(ip="server-startup", detection=det, extra_details="Startup integrity check failed")
        except Exception:
            pass


def verify_or_raise_on_startup() -> None:
    """Verification entrypoint for the startup flow.

    Raises RuntimeError on failure.
    """

    result = verify_integrity()

    if result.passed:
        # Success logging (non-critical): keep as print + optional log_threat if available.
        try:
            from .logger import logging as _logging  # type: ignore

            _logging.info("[integrity] Integrity Check Passed")
        except Exception:
            pass

        print("[integrity] Integrity Check Passed")
        return

    # Failure path: create security alert + log incident, then block startup.
    _create_integrity_alert_and_log(result)
    print("[integrity] Integrity Verification Failed; startup blocked")
    return _raise_startup_blocked()


def _raise_startup_blocked() -> None:
    raise RuntimeError("Integrity verification failed")


