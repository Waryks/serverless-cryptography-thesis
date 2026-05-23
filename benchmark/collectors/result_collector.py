from __future__ import annotations

from dataclasses import dataclass

from benchmark.collectors.audit_collector import AuditCollector
from benchmark.collectors.ledger_collector import LedgerCollector


@dataclass(frozen=True)
class CompletionResult:
    outcome: str
    matched: bool
    record: dict | None
    completed_at_ms: int | None


class ResultCollector:
    def __init__(self, ledger_collector: LedgerCollector, audit_collector: AuditCollector) -> None:
        self._ledger = ledger_collector
        self._audit = audit_collector

    def wait_for_outcome(
        self,
        expected_outcome: str,
        event_id: str,
        timeout_seconds: float,
        poll_seconds: float,
    ) -> CompletionResult:
        if expected_outcome == "ACCEPTED":
            item = self._ledger.wait_for_event(event_id, timeout_seconds, poll_seconds)
            completed_at_ms = _as_int(item, "persistedAtEpochMs") if item else None
            return CompletionResult(
                outcome="ACCEPTED",
                matched=item is not None,
                record=item,
                completed_at_ms=completed_at_ms,
            )

        item = self._audit.wait_for_event(event_id, timeout_seconds, poll_seconds)
        completed_at_ms = _as_int(item, "persistedAtEpochMs") if item else None
        return CompletionResult(
            outcome="REJECTED",
            matched=item is not None,
            record=item,
            completed_at_ms=completed_at_ms,
        )


def _as_int(item: dict, key: str) -> int | None:
    if not item or key not in item:
        return None
    value = item[key]
    if "N" in value:
        return int(value["N"])
    if "S" in value and value["S"].isdigit():
        return int(value["S"])
    return None

