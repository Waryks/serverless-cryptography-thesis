from __future__ import annotations

from benchmark.scenarios.duplicate_scenario import build_duplicate_events


def build_replay_events(algorithm: str, key_id: str, payload_size: str) -> tuple[dict, dict]:
    return build_duplicate_events(algorithm=algorithm, key_id=key_id, payload_size=payload_size)
