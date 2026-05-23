from __future__ import annotations

from benchmark.generators.event_generator import EventBuildOptions, generate_unsigned_event


def build_event(algorithm: str, key_id: str | None = None, payload_size: str = "small", event_id: str | None = None) -> dict:
    """Builds an event that references a nonexistent key id.

    The validator should attempt key resolution and produce UNKNOWN_KEY (or INVALID_SIGNATURE
    depending on policy) in the audit record.
    """
    # Use a deliberately unknown key identifier when one is not supplied
    unknown_key = key_id or "unknown-key-DOES_NOT_EXIST"
    event = generate_unsigned_event(
        EventBuildOptions(algorithm=algorithm, key_id=unknown_key, payload_size=payload_size, event_id=event_id)
    )
    event["signatureB64"] = "SIGNATURE_USING_UNKNOWN_KEY"
    return event

