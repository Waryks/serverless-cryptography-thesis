"""
Story 14: Integration example showing how to use the configuration system.

This demonstrates the recommended pattern for configurable experiment orchestration.
"""

from pathlib import Path
from benchmark.models import (
    ScenarioLoader,
    ScenarioValidator,
    ExperimentDefinition,
    ResultValidator,
)


def example_load_and_validate_experiments():
    """Example: Load experiments and validate configuration."""

    # Load experiments from YAML
    config_path = Path("benchmark/config/experiment_config_story14.yaml")
    experiments = ScenarioLoader.load_from_file(config_path)

    print(f"Loaded {len(experiments)} experiments")

    # Validate all experiments
    validation_errors = ScenarioValidator.validate_all(experiments)

    if validation_errors:
        print("Validation errors found:")
        for experiment_id, errors in validation_errors.items():
            print(f"  {experiment_id}:")
            for error in errors:
                print(f"    - {error}")
    else:
        print("All experiments valid!")

    # Display experiments
    for exp in experiments:
        print(f"\n  {exp.experiment_id}")
        print(f"    Scenario: {exp.scenario}")
        print(f"    Algorithm: {exp.crypto_config.algorithm.value}")
        print(f"    Iterations: {exp.iterations}")
        print(f"    Fingerprint: {exp.compute_fingerprint()}")
        print(f"    Cold Start: {exp.is_cold_start_scenario()}")


def example_experiment_configuration_variations():
    """Example: Create experiments programmatically with various configurations."""

    from benchmark.models import (
        Algorithm,
        PayloadSize,
        ColdStartMode,
        CacheMode,
        RotationMode,
        ExecutionMode,
        ExpectedOutcome,
        ReplayDedupConfig,
        CryptoConfig,
        WorkloadConfig,
        ColdStartConfig,
        ExperimentDefinition,
    )

    # Example 1: Baseline HMAC test
    baseline_hmac = ExperimentDefinition(
        experiment_id="baseline_hmac_warm",
        description="Baseline HMAC with warm invocations",
        scenario="accepted",
        crypto_config=CryptoConfig(
            algorithm=Algorithm.HMAC_SHA256,
            cache_enabled=False,
            rotation_mode=RotationMode.CURRENT_ONLY,
        ),
        workload_config=WorkloadConfig(
            payload_size=PayloadSize.SMALL,
            execution_mode=ExecutionMode.SEQUENTIAL,
        ),
        cold_start_config=ColdStartConfig(
            mode=ColdStartMode.NONE,
        ),
        replay_dedup_config=ReplayDedupConfig(
            replay_enabled=True,
            dedup_enabled=True,
        ),
        iterations=50,
        expected_outcome=ExpectedOutcome.ACCEPTED,
    )

    print(f"Experiment: {baseline_hmac.experiment_id}")
    print(f"  Config: {baseline_hmac.to_dict()}")
    print(f"  Fingerprint: {baseline_hmac.compute_fingerprint()}")

    # Example 2: RSA with cache and key rotation
    rsa_with_cache_and_rotation = ExperimentDefinition(
        experiment_id="rsa_cache_rotation",
        description="RSA with cache and key rotation support",
        scenario="accepted",
        crypto_config=CryptoConfig(
            algorithm=Algorithm.RSA_PSS_SHA256,
            cache_enabled=True,
            rotation_mode=RotationMode.CURRENT_AND_PREVIOUS,
        ),
        workload_config=WorkloadConfig(
            payload_size=PayloadSize.MEDIUM,
            execution_mode=ExecutionMode.SEQUENTIAL,
        ),
        cold_start_config=ColdStartConfig(
            mode=ColdStartMode.PER_ITERATION,
        ),
        replay_dedup_config=ReplayDedupConfig(
            replay_enabled=True,
            dedup_enabled=True,
        ),
        iterations=10,
        expected_outcome=ExpectedOutcome.ACCEPTED,
    )

    print(f"\nExperiment: {rsa_with_cache_and_rotation.experiment_id}")
    print(f"  Algorithm: {rsa_with_cache_and_rotation.crypto_config.algorithm.value}")
    print(f"  Cache Enabled: {rsa_with_cache_and_rotation.crypto_config.cache_enabled}")
    print(f"  Rotation Mode: {rsa_with_cache_and_rotation.crypto_config.rotation_mode.value}")
    print(f"  Cold Start: {rsa_with_cache_and_rotation.is_cold_start_scenario()}")

    # Example 3: Replay attack scenario
    replay_scenario = ExperimentDefinition(
        experiment_id="ecdsa_replay_attack",
        description="ECDSA replay attack detection test",
        scenario="replay",
        crypto_config=CryptoConfig(
            algorithm=Algorithm.ECDSA_P256_SHA256,
            cache_enabled=False,
        ),
        workload_config=WorkloadConfig(
            payload_size=PayloadSize.SMALL,
        ),
        cold_start_config=ColdStartConfig(
            mode=ColdStartMode.NONE,
        ),
        replay_dedup_config=ReplayDedupConfig(
            replay_enabled=True,
            dedup_enabled=True,
            replay_window_ms=300000,
        ),
        iterations=3,
        expected_outcome=ExpectedOutcome.REJECTED,
    )

    print(f"\nExperiment: {replay_scenario.experiment_id}")
    print(f"  Scenario: {replay_scenario.scenario}")
    print(f"  Is Replay Scenario: {replay_scenario.is_replay_scenario()}")
    print(f"  Expected Outcome: {replay_scenario.expected_outcome.value}")
    print(f"  Replay Window: {replay_scenario.replay_dedup_config.replay_window_ms}ms")


def example_result_classification():
    """Example: Classify and validate execution results."""

    from benchmark.models import (
        ScenarioExecutionResult,
        ExpectedOutcome,
        ResultValidator,
    )

    # Create example experiment
    from benchmark.models import (
        Algorithm,
        PayloadSize,
        ColdStartMode,
        CacheMode,
        RotationMode,
        ExecutionMode,
        ReplayDedupConfig,
        CryptoConfig,
        WorkloadConfig,
        ColdStartConfig,
        ExperimentDefinition,
    )

    experiment = ExperimentDefinition(
        experiment_id="test_exp",
        description="Test",
        scenario="accepted",
        crypto_config=CryptoConfig(algorithm=Algorithm.HMAC_SHA256),
        workload_config=WorkloadConfig(payload_size=PayloadSize.SMALL),
        cold_start_config=ColdStartConfig(mode=ColdStartMode.NONE),
        replay_dedup_config=ReplayDedupConfig(),
        iterations=1,
        expected_outcome=ExpectedOutcome.ACCEPTED,
    )

    # Create example results
    result_success = ScenarioExecutionResult(
        experiment_id="test_exp",
        iteration=0,
        event_id="evt-123",
        latency_ms=45.3,
        outcome=ExpectedOutcome.ACCEPTED,
        is_cold_start=False,
        success=True,
    )

    result_mismatch = ScenarioExecutionResult(
        experiment_id="test_exp",
        iteration=1,
        event_id="evt-124",
        latency_ms=42.1,
        outcome=ExpectedOutcome.REJECTED,
        is_cold_start=False,
        success=False,
    )

    # Classify results
    classified_success = ResultValidator.classify(result_success, experiment)
    classified_mismatch = ResultValidator.classify(result_mismatch, experiment)

    print(f"\nResult 1: {classified_success.classification.value}")
    print(f"  Event: {classified_success.result.event_id}")
    print(f"  Latency: {classified_success.result.latency_ms}ms")

    print(f"\nResult 2: {classified_mismatch.classification.value}")
    print(f"  Event: {classified_mismatch.result.event_id}")
    print(f"  Latency: {classified_mismatch.result.latency_ms}ms")

    # Summarize results
    all_classified = [classified_success, classified_mismatch]
    summary = ResultValidator.summarize(all_classified)

    print(f"\nSummary:")
    print(f"  Total: {summary['total']}")
    print(f"  Successes: {summary['successes']}")
    print(f"  Mismatches: {summary['mismatches']}")
    print(f"  Success Rate: {summary['success_rate']:.1%}")
    print(f"  Avg Latency: {summary['avg_latency_ms']:.1f}ms")


if __name__ == "__main__":
    print("=" * 70)
    print("Story 14: Configuration System Integration Examples")
    print("=" * 70)

    print("\n[Example 1: Load and Validate Experiments]")
    print("-" * 70)
    # example_load_and_validate_experiments()
    print("(Requires benchmark setup)")

    print("\n[Example 2: Programmatic Configuration]")
    print("-" * 70)
    example_experiment_configuration_variations()

    print("\n[Example 3: Result Classification]")
    print("-" * 70)
    example_result_classification()

    print("\n" + "=" * 70)
    print("Configuration system supports all experiment variations!")
    print("=" * 70)

