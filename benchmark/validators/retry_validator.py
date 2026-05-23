from __future__ import annotations

"""Simple rules to determine whether a given outcome should trigger retries.

This module codifies the distinction between security rejections (no retry)
and infrastructure failures (retry). The mapping is conservative and intended
for use by smoke tests and reports.
"""

_NO_RETRY_REASONS = {
    "INVALID_SIGNATURE",
    "EXPIRED",
    "REPLAY_DETECTED",
    "UNKNOWN_KEY",
    "ALGORITHM_MISMATCH",
    "POLICY_REJECTED",
    "DESERIALIZATION_ERROR",
}


def is_retry_expected(audit_reason: str | None) -> bool:
    """Return True if the provided audit_reason indicates a retry should occur.

    If audit_reason is None (unknown), conservatively return False.
    """
    if not audit_reason:
        return False
    return audit_reason not in _NO_RETRY_REASONS

