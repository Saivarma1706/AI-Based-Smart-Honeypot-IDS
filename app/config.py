import os
import sys


# Project root is one directory above this file (app/ -> project root)
# Preserved for dev mode and for read-only bundle assets.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Writable runtime directory (Phase 7 Task 2)
# ---------------------------------------------------------------------------
# In a PyInstaller build, PROJECT_ROOT points into the read-only _internal/
# bundle.  data/ and logs/ must instead live in a writable, per-user location.
#
# Resolution order for RUNTIME_ROOT:
#   1. SMARTHONEYPOTIDS_PORTABLE=1  -> EXE folder (portable mode)
#   2. %LOCALAPPDATA%\SmartHoneypotIDS\   (default when frozen)
#   3. EXE folder (last-resort fallback when LOCALAPPDATA is unwritable)
#
# In unfrozen (development) mode, RUNTIME_ROOT is the project root so that
# existing dev behaviour is preserved exactly.


def _is_writable_dir(path: str) -> bool:
    """Return True if `path` exists or can be created and is writable."""
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write_probe")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        return True
    except (OSError, PermissionError):
        return False


def _exe_or_project_root() -> str:
    """Return the EXE directory when frozen, else the project root."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return PROJECT_ROOT


def runtime_root() -> str:
    """Return the writable root directory for data/ and logs/.

    - SMARTHONEYPOTIDS_PORTABLE=1  -> EXE folder (portable install)
    - Frozen + LOCALAPPDATA writable -> %LOCALAPPDATA%\\SmartHoneypotIDS\\
    - Frozen + LOCALAPPDATA unusable -> EXE folder (fallback)
    - Unfrozen (dev)                  -> project root (unchanged)
    """
    # 1. Explicit portable override
    if os.environ.get("SMARTHONEYPOTIDS_PORTABLE") == "1":
        return _exe_or_project_root()

    # 2. Per-user default (frozen builds only)
    if getattr(sys, "frozen", False):
        local = os.environ.get("LOCALAPPDATA") or ""
        if local:
            candidate = os.path.join(local, "SmartHoneypotIDS")
            if _is_writable_dir(candidate):
                return candidate

    # 3. Last-resort fallback for frozen builds; project root for dev
    return _exe_or_project_root()


# Writable runtime root (used for data/ and logs/).
RUNTIME_ROOT = runtime_root()


# SQLite DB path (created automatically at first connection).
DB_PATH = os.path.join(RUNTIME_ROOT, "data", "honeypot_ids.db")

# Log directory and log file path.
LOG_DIR = os.path.join(RUNTIME_ROOT, "logs")
LOG_PATH = os.path.join(LOG_DIR, "honeypot.log")


# ML model artifact path (read-only bundle asset; keep resolved from __file__).
# In a PyInstaller build, this resolves via sys._MEIPASS; in dev it is the
# project tree.  In both cases the model is treated as bundled/read-only.
if getattr(sys, "frozen", False):
    _MODEL_ROOT = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
else:
    _MODEL_ROOT = PROJECT_ROOT
MODEL_PATH = os.path.join(_MODEL_ROOT, "models", "anomaly_model.joblib")

# --- Detection thresholds (beginner-friendly defaults) ---
# Brute-force rule: if N failed attempts happen within WINDOW_SECONDS -> alert
BRUTE_FORCE_WINDOW_SECONDS = 120
BRUTE_FORCE_FAILS_THRESHOLD = 8

# Suspicion scoring
SUSPICIOUS_SCORE_THRESHOLD = 70  # if score >= threshold -> alert

# When building AI features, keep at most this many recent attempts
RECENT_ATTEMPTS_LIMIT = 200

# --- Rate limiting & temporary IP blocking (Phase 5 Task 1) ---
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_FAILS_THRESHOLD = 10
RATE_LIMIT_BLOCK_MINUTES = 15

RATE_LIMIT_BLOCKED = "RATE_LIMIT_BLOCKED"
RATE_LIMIT_BLOCK_EVENT = "RATE_LIMIT_BLOCK"
RATE_LIMIT_ALERT_TYPE = "HONEYPOT_RATE_LIMIT_BLOCK"


