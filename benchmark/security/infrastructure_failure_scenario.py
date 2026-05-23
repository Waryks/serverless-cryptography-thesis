from __future__ import annotations

from benchmark.generators.event_generator import EventBuildOptions, generate_unsigned_event


def build_event(algorithm: str, key_id: str, payload_size: str, event_id: str | None = None, force: dict | None = None) -> dict:
    """Build an event that carries flags instructing the test harness to inject failures.

    This simple approach uses an explicit flag inside the event content so LocalStack
    smoke tests or instrumented lambdas can simulate DynamoDB/SQS/Secrets failures.
    """
    event = generate_unsigned_event(
        EventBuildOptions(algorithm=algorithm, key_id=key_id, payload_size=payload_size, event_id=event_id)
    )
    # Add an explicit failure-injection hint. The platform's test harness is expected
    # to recognise this field and perform the appropriate temporary resource manipulation
    # or throw an error during validation/persistence.
    event.setdefault("content", {})
    event["content"]["_failure_injection"] = force or {"dynamo": True}
    event["signatureB64"] = "VALID_SIGNATURE_PLACEHOLDER"
    return event

