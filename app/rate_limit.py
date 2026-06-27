from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

try:
    from .config import (
        RATE_LIMIT_FAILS_THRESHOLD,
    )
except ImportError:  # pragma: no cover
    from config import (
        RATE_LIMIT_FAILS_THRESHOLD,
    )


@dataclass(frozen=True)
class RateLimitDecision:
    blocked: bool
    failed_attempts_in_window: int
    now: datetime


def should_block(failed_attempts_in_window: int) -> bool:
    return failed_attempts_in_window >= RATE_LIMIT_FAILS_THRESHOLD


