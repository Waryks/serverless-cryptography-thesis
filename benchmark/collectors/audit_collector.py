from __future__ import annotations

import time
from typing import Any


class AuditCollector:
    def __init__(self, dynamodb_client: Any, audit_table: str) -> None:
        self._dynamodb = dynamodb_client
        self._audit_table = audit_table

    def wait_for_event(self, event_id: str, timeout_seconds: float, poll_seconds: float) -> dict | None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            item = self.fetch_event(event_id)
            if item:
                return item
            time.sleep(poll_seconds)
        return None

    def fetch_event(self, event_id: str) -> dict | None:
        response = self._dynamodb.scan(
            TableName=self._audit_table,
            FilterExpression="eventId = :eventId",
            ExpressionAttributeValues={":eventId": {"S": event_id}},
            Limit=1,
        )
        items = response.get("Items", [])
        return items[0] if items else None

