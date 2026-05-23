from __future__ import annotations

from benchmark.scenarios.accepted_flow import build_event


def build_duplicate_events(algorithm: str, key_id: str, payload_size: str) -> tuple[dict, dict]:
    seed = build_event(algorithm=algorithm, key_id=key_id, payload_size=payload_size)
    event_id = seed["content"]["eventId"]
    return seed, build_event(
        algorithm=algorithm,
        key_id=key_id,
        payload_size=payload_size,
        event_id=event_id,
    )
