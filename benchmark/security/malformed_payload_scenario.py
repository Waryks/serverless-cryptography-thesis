from __future__ import annotations

from benchmark.generators.event_generator import EventBuildOptions, generate_unsigned_event


def build_event(algorithm: str, key_id: str, payload_size: str, event_id: str | None = None) -> dict:
    """Builds an event with a malformed payload that should fail deserialization.

    The validation lambda is expected to raise a deserialization error and the audit
    reason DESERIALIZATION_ERROR should be persisted.
    """
    event = generate_unsigned_event(
        EventBuildOptions(algorithm=algorithm, key_id=key_id, payload_size=payload_size, event_id=event_id)
    )

    # Replace the structured payload with intentionally malformed data (string instead of object).
    event["content"]["payload"] = "{ this is not valid JSON :::"
    # Signature is irrelevant for deserialization errors but include a placeholder.
    event["signatureB64"] = "INVALID_BASE64_PAYLOAD"
    return event

