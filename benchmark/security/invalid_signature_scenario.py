from __future__ import annotations

from benchmark.generators.event_generator import EventBuildOptions, generate_unsigned_event


def build_event(algorithm: str, key_id: str, payload_size: str, event_id: str | None = None) -> dict:
    """Builds an event with an intentionally invalid/corrupted signature.

    The validator should reject this event with an INVALID_SIGNATURE audit reason.
    """
    event = generate_unsigned_event(
        EventBuildOptions(algorithm=algorithm, key_id=key_id, payload_size=payload_size, event_id=event_id)
    )

    # Corrupt the signature field to simulate an invalid signature being supplied.
    event["signatureB64"] = "CORRUPTED_SIGNATURE"
    return event

