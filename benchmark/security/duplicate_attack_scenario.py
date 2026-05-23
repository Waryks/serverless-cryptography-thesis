from __future__ import annotations

from benchmark.generators.event_generator import EventBuildOptions, generate_unsigned_event


def build_event(algorithm: str, key_id: str, payload_size: str, event_id: str) -> dict:
    """Build an event that can be sent twice to trigger deduplication/replay detection.

    The duplicate scenario requires the caller to supply the same event_id for both sends.
    """
    event = generate_unsigned_event(
        EventBuildOptions(algorithm=algorithm, key_id=key_id, payload_size=payload_size, event_id=event_id)
    )
    event["signatureB64"] = "VALID_SIGNATURE_PLACEHOLDER"
    return event

