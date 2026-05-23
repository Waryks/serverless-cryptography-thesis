from __future__ import annotations

import time
from dataclasses import dataclass

from benchmark.generators.payload_generator import generate_payload
from benchmark.generators.random_data import random_uuid


@dataclass(frozen=True)
class EventBuildOptions:
    algorithm: str
    key_id: str
    payload_size: str
    timestamp_epoch_ms: int | None = None
    event_id: str | None = None


def generate_unsigned_event(options: EventBuildOptions) -> dict:
    timestamp_epoch_ms = options.timestamp_epoch_ms or int(time.time() * 1000)
    event_id = options.event_id or random_uuid()

    return {
        "content": {
            "eventId": event_id,
            "timestampEpochMs": timestamp_epoch_ms,
            "algorithm": options.algorithm,
            "keyId": options.key_id,
            "payload": generate_payload(options.payload_size),
        },
        "signatureB64": None,
    }
