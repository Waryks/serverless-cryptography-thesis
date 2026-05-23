from __future__ import annotations

import time
from typing import Any


class LedgerCollector:
    def __init__(self, dynamodb_client: Any, ledger_table: str) -> None:
        self._dynamodb = dynamodb_client
        self._ledger_table = ledger_table

    def wait_for_event(self, event_id: str, timeout_seconds: float, poll_seconds: float) -> dict | None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            item = self.fetch_event(event_id)
            if item:
                return item
            time.sleep(poll_seconds)
        return None

    def fetch_event(self, event_id: str) -> dict | None:
        response = self._dynamodb.get_item(
            TableName=self._ledger_table,
            Key={"eventId": {"S": event_id}},
        )
        return response.get("Item")
