from __future__ import annotations

"""Helpers to validate audit items returned from the audit table.

The DynamoDB items returned by the collectors are expected to be the raw
attribute maps (e.g. {'reason': {'S': 'INVALID_SIGNATURE'}, ...}). This module
provides small helpers to extract and compare those fields robustly.
"""

from typing import Any


def extract_reason(audit_item: dict | None) -> str | None:
    """Extract the textual audit reason from a raw DynamoDB item.

    Supports both the raw DynamoDB attribute value form and a plain dict where the
    reason is already a string (used by some test doubles).
    """
    if not audit_item:
        return None

    if "reason" not in audit_item:
        # Some representations may use 'rejectionReason' or similar; support a couple
        alt = audit_item.get("rejectionReason") or audit_item.get("auditReason")
        if isinstance(alt, dict) and "S" in alt:
            return alt["S"]
        if isinstance(alt, str):
            return alt
        return None

    value = audit_item["reason"]
    if isinstance(value, dict) and "S" in value:
        return value["S"]
    if isinstance(value, str):
        return value
    return None


def matches_expected(audit_item: dict | None, expected_reason: str | None) -> bool:
    if expected_reason is None:
        # No expectation -> presence is enough
        return audit_item is not None
    reason = extract_reason(audit_item)
    return reason == expected_reason

