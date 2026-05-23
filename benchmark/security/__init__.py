"""Security scenario helpers for the benchmark.

This package contains simple scenario builders used by tests and the
benchmark runner to produce intentionally invalid or failure-inducing
events. The implementations are intentionally small and explicit so they
are easy to extend.
"""

__all__ = [
    "invalid_signature_scenario",
    "replay_attack_scenario",
    "duplicate_attack_scenario",
    "malformed_payload_scenario",
    "unknown_key_scenario",
    "infrastructure_failure_scenario",
]

