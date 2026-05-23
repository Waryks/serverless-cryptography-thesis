from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class RejectionRow:
    scenario: str
    expected_outcome: str
    actual_outcome: str
    latency_ms: int | None
    retry_expected: bool
    audit_reason: str | None
    success: bool


def to_dict(row: RejectionRow) -> dict:
    return asdict(row)


def make_row(scenario: str, classification: Any) -> dict:
    """Convert a Classification (from outcome_validator) into a flat row suitable for CSV/JSON export."""
    return to_dict(
        RejectionRow(
            scenario=scenario,
            expected_outcome=classification.expected_outcome,
            actual_outcome=classification.actual_outcome,
            latency_ms=classification.latency_ms,
            retry_expected=classification.retry_expected,
            audit_reason=classification.audit_reason,
            success=classification.success,
        )
    )

