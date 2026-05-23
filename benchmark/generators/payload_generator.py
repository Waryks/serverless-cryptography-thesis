from __future__ import annotations

from benchmark.generators.random_data import random_float, random_int, random_string, random_uuid

_PAYLOAD_PROFILES = {
    "small": (2, 48),
    "medium": (8, 256),
    "large": (20, 1024),
}


def generate_payload(payload_size: str) -> dict:
    if payload_size not in _PAYLOAD_PROFILES:
        raise ValueError(f"Unsupported payload size: {payload_size}")

    fields, text_length = _PAYLOAD_PROFILES[payload_size]
    nested_items = []
    for index in range(fields):
        nested_items.append(
            {
                "position": index,
                "token": random_uuid(),
                "name": random_string(16),
                "count": random_int(),
                "value": random_float(),
            }
        )

    return {
        "payloadProfile": payload_size,
        "note": random_string(text_length),
        "items": nested_items,
    }
