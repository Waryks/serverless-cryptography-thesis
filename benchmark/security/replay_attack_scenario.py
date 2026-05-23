from __future__ import annotations

import time
from benchmark.generators.event_generator import EventBuildOptions, generate_unsigned_event


def build_event(algorithm: str, key_id: str, payload_size: str, event_id: str | None = None, replay_window_ms: int = 300_000) -> dict:
    """Build an event that appears older than the replay window to trigger EXPIRED.

    The timestamp is set to now - (replay_window_ms + 1s).
    """
    old_timestamp = int(time.time() * 1000) - (replay_window_ms + 1_000)
    event = generate_unsigned_event(EventBuildOptions(algorithm=algorithm, key_id=key_id, payload_size=payload_size, timestamp_epoch_ms=old_timestamp, event_id=event_id))
    # Signature can be valid for this scenario; the timestamp alone should trigger expiry
    event["signatureB64"] = "VALID_SIGNATURE_PLACEHOLDER"
    return event

