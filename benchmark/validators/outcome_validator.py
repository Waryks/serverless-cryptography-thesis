from __future__ import annotations

"""Classify and validate completion results against expectations.

This module works with the benchmark.collectors.ResultCollector.CompletionResult
structure (a simple dataclass with fields: outcome, matched, record, completed_at_ms).
"""

from dataclasses import dataclass
from typing import Any

from benchmark.validators.audit_validator import extract_reason
from benchmark.validators.retry_validator import is_retry_expected


@dataclass
class Classification:
    success: bool
    message: str
    expected_outcome: str
    actual_outcome: str
    audit_reason: str | None = None
    latency_ms: int | None = None
    retry_expected: bool = False


def classify(completion_result: Any, expected_outcome: str, expected_audit_reason: str | None = None) -> Classification:
    actual = completion_result.outcome if hasattr(completion_result, "outcome") else "UNKNOWN"
    matched = getattr(completion_result, "matched", False)
    record = getattr(completion_result, "record", None)
    latency = getattr(completion_result, "completed_at_ms", None)

    audit_reason = extract_reason(record) if record else None
    retry_expected = is_retry_expected(audit_reason)

    if expected_outcome == actual and matched:
        return Classification(
            success=True,
            message="Outcome matched expectation",
            expected_outcome=expected_outcome,
            actual_outcome=actual,
            audit_reason=audit_reason,
            latency_ms=latency,
            retry_expected=retry_expected,
        )

    # Mismatch or missing record
    return Classification(
        success=False,
        message=f"Expected {expected_outcome} but got {actual} (matched={matched})",
        expected_outcome=expected_outcome,
        actual_outcome=actual,
        audit_reason=audit_reason,
        latency_ms=latency,
        retry_expected=retry_expected,
    )

