from __future__ import annotations

import time

from benchmark.generators.event_generator import EventBuildOptions, generate_unsigned_event


def build_expired_event(
    algorithm: str,
    key_id: str,
    payload_size: str,
    replay_window_ms: int,
    event_id: str | None = None,
) -> dict:
    stale_timestamp = int(time.time() * 1000) - replay_window_ms - 1000
    return generate_unsigned_event(
        EventBuildOptions(
            algorithm=algorithm,
            key_id=key_id,
            payload_size=payload_size,
            timestamp_epoch_ms=stale_timestamp,
            event_id=event_id,
        )
    )
