#!/usr/bin/env python3
"""Simple test of Story 14 core models."""

import sys
sys.path.insert(0, '.')

from benchmark.models.experiment_definition import (
    Algorithm,
    PayloadSize,
    ColdStartMode,
    RotationMode,
    ExecutionMode,
    ExpectedOutcome,
    CryptoConfig,
    WorkloadConfig,
    ColdStartConfig,
    ReplayDedupConfig,
    ExperimentDefinition,
    ScenarioExecutionResult,
)

def main():
    print("Story 14: Testing Experiment Definition Models")
    print("=" * 60)

    # Test 1: Basic experiment
    exp1 = ExperimentDefinition(
        experiment_id="test_hmac",
        description="Test HMAC",
        scenario="accepted",
        crypto_config=CryptoConfig(algorithm=Algorithm.HMAC_SHA256),
        workload_config=WorkloadConfig(payload_size=PayloadSize.SMALL),
        cold_start_config=ColdStartConfig(mode=ColdStartMode.NONE),
        replay_dedup_config=ReplayDedupConfig(),
        iterations=5,
        expected_outcome=ExpectedOutcome.ACCEPTED,
    )

    print(f"\n✓ Experiment 1: {exp1.experiment_id}")
    print(f"  Algorithm: {exp1.crypto_config.algorithm.value}")
    print(f"  Fingerprint: {exp1.compute_fingerprint()}")

    # Test 2: Complex experiment
    exp2 = ExperimentDefinition(
        experiment_id="test_rsa_advanced",
        description="RSA with cache and rotation",
        scenario="accepted",
        crypto_config=CryptoConfig(
            algorithm=Algorithm.RSA_PSS_SHA256,
            cache_enabled=True,
            rotation_mode=RotationMode.CURRENT_AND_PREVIOUS,
        ),
        workload_config=WorkloadConfig(
            payload_size=PayloadSize.LARGE,
            execution_mode=ExecutionMode.SEQUENTIAL,
        ),
        cold_start_config=ColdStartConfig(mode=ColdStartMode.PER_ITERATION),
        replay_dedup_config=ReplayDedupConfig(),
        iterations=10,
        expected_outcome=ExpectedOutcome.ACCEPTED,
    )

    print(f"\n✓ Experiment 2: {exp2.experiment_id}")
    print(f"  Algorithm: {exp2.crypto_config.algorithm.value}")
    print(f"  Cache: {exp2.crypto_config.cache_enabled}")
    print(f"  Rotation: {exp2.crypto_config.rotation_mode.value}")
    print(f"  Cold Start: {exp2.is_cold_start_scenario()}")

    # Test 3: Export to dict
    config = exp2.to_dict()
    print(f"\n✓ Export to dict: {len(config)} keys")

    # Test 4: Result
    result = ScenarioExecutionResult(
        experiment_id="test_hmac",
        iteration=0,
        event_id="evt-123",
        latency_ms=45.3,
        outcome=ExpectedOutcome.ACCEPTED,
        is_cold_start=False,
        success=True,
    )
    print(f"\n✓ Result: {result.event_id} ({result.latency_ms}ms)")

    print("\n" + "=" * 60)
    print("All tests passed!")

if __name__ == "__main__":
    main()

