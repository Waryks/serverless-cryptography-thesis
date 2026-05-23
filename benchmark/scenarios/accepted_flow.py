from __future__ import annotations

from benchmark.generators.event_generator import EventBuildOptions, generate_unsigned_event


def build_event(algorithm: str, key_id: str, payload_size: str, event_id: str | None = None) -> dict:
    return generate_unsigned_event(
        EventBuildOptions(
            algorithm=algorithm,
            key_id=key_id,
            payload_size=payload_size,
            event_id=event_id,
        )
    )
