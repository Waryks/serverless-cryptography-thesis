"""
Story 14: Scenario configuration loader for reproducible experiments.

Loads YAML experiment definitions and transforms them into strongly-typed
configuration models with validation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None

from benchmark.models.experiment_definition import (
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


class ScenarioLoader:
    """Loads and parses YAML experiment configurations."""

    @staticmethod
    def load_from_file(config_path: Path | str) -> list[ExperimentDefinition]:
        """
        Load experiments from YAML file.

        Args:
            config_path: Path to experiment_config.yaml

        Returns:
            List of ExperimentDefinition objects

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If YAML is invalid or required fields missing
            ImportError: If PyYAML is not installed
        """
        if yaml is None:
            raise ImportError("PyYAML is required for scenario loading. Install with: pip install PyYAML")

        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        experiments = []

        for item in data.get("experiments", []):
            try:
                experiment = ScenarioLoader._parse_experiment(item)
                experiments.append(experiment)
            except ValueError as e:
                raise ValueError(
                    f"Failed to parse experiment '{item.get('name', 'unknown')}': {e}"
                ) from e

        return experiments

    @staticmethod
    def _parse_experiment(item: dict[str, Any]) -> ExperimentDefinition:
        """Parse single experiment from YAML dict."""

        # Required fields
        name = item.get("name")
        if not name:
            raise ValueError("Missing required field: 'name'")

        scenario = item.get("scenario")
        if not scenario:
            raise ValueError("Missing required field: 'scenario'")

        # Parse algorithm
        algorithm_str = item.get("algorithm", "HMAC_SHA256")
        try:
            algorithm = Algorithm[algorithm_str]
        except KeyError:
            raise ValueError(f"Unknown algorithm: {algorithm_str}")

        # Parse payload size
        payload_size_str = item.get("payload_size", "small")
        try:
            payload_size = PayloadSize[payload_size_str.upper()]
        except KeyError:
            raise ValueError(f"Unknown payload_size: {payload_size_str}")

        # Parse cold start mode
        cold_start_mode_str = item.get("cold_start_mode", "none")
        try:
            cold_start_mode = ColdStartMode[cold_start_mode_str.upper()]
        except KeyError:
            raise ValueError(f"Unknown cold_start_mode: {cold_start_mode_str}")

        # Parse rotation mode if provided
        rotation_mode_str = item.get("rotation_mode", "current_only")
        try:
            rotation_mode = RotationMode[rotation_mode_str.upper()]
        except KeyError:
            raise ValueError(f"Unknown rotation_mode: {rotation_mode_str}")

        # Parse execution mode if provided
        execution_mode_str = item.get("execution_mode", "sequential")
        try:
            execution_mode = ExecutionMode[execution_mode_str.upper()]
        except KeyError:
            raise ValueError(f"Unknown execution_mode: {execution_mode_str}")

        # Parse expected outcome
        expected_outcome_str = item.get("expected_outcome", "ACCEPTED")
        try:
            expected_outcome = ExpectedOutcome[expected_outcome_str.upper()]
        except KeyError:
            raise ValueError(f"Unknown expected_outcome: {expected_outcome_str}")

        # Parse cache mode
        cache_enabled = item.get("cache_enabled", False)

        # Parse iterations
        iterations = int(item.get("iterations", 1))
        if iterations < 1:
            raise ValueError("iterations must be >= 1")

        # Build configuration objects
        crypto_config = CryptoConfig(
            algorithm=algorithm,
            cache_enabled=cache_enabled,
            rotation_mode=rotation_mode,
        )

        workload_config = WorkloadConfig(
            payload_size=payload_size,
            execution_mode=execution_mode,
        )

        cold_start_config = ColdStartConfig(
            mode=cold_start_mode,
            idle_wait_seconds=float(item.get("idle_wait_seconds", 0.0)),
        )

        replay_dedup_config = ReplayDedupConfig(
            replay_enabled=item.get("replay_enabled", True),
            dedup_enabled=item.get("dedup_enabled", True),
            replay_window_ms=int(item.get("replay_window_ms", 300000)),
        )

        # Create experiment definition
        experiment = ExperimentDefinition(
            experiment_id=name,
            description=item.get("description", f"Experiment {name}"),
            scenario=scenario,
            crypto_config=crypto_config,
            workload_config=workload_config,
            cold_start_config=cold_start_config,
            replay_dedup_config=replay_dedup_config,
            iterations=iterations,
            expected_outcome=expected_outcome,
            completion_timeout_seconds=float(item.get("completion_timeout_seconds", 8.0)),
            poll_interval_seconds=float(item.get("poll_seconds", 0.25)),
            key_id=item.get("key_id"),
            tags=item.get("tags", {}),
        )

        return experiment


class ScenarioValidator:
    """Validates experiment configuration for consistency and completeness."""

    @staticmethod
    def validate(experiment: ExperimentDefinition) -> list[str]:
        """
        Validate experiment configuration.

        Args:
            experiment: ExperimentDefinition to validate

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate scenario type
        valid_scenarios = {"accepted", "rejected", "replay", "duplicate", "expired"}
        if experiment.scenario not in valid_scenarios:
            errors.append(f"Invalid scenario: {experiment.scenario}")

        # Validate replay/dedup combination
        if not experiment.replay_dedup_config.replay_enabled and \
           not experiment.replay_dedup_config.dedup_enabled:
            if experiment.scenario in ("replay", "duplicate", "expired"):
                errors.append(
                    "Replay/dedup scenarios require at least one of "
                    "replay_enabled or dedup_enabled"
                )

        # Validate timing constraints
        if experiment.completion_timeout_seconds <= 0:
            errors.append("completion_timeout_seconds must be > 0")

        if experiment.poll_interval_seconds <= 0:
            errors.append("poll_interval_seconds must be > 0")

        if experiment.poll_interval_seconds > experiment.completion_timeout_seconds:
            errors.append(
                "poll_interval_seconds must be <= completion_timeout_seconds"
            )

        # Validate cold start mode with idle wait
        if experiment.cold_start_config.mode == ColdStartMode.IDLE_WAIT:
            if experiment.cold_start_config.idle_wait_seconds <= 0:
                errors.append(
                    "IDLE_WAIT mode requires idle_wait_seconds > 0"
                )

        # Validate replay window
        if experiment.replay_dedup_config.replay_window_ms <= 0:
            errors.append("replay_window_ms must be > 0")

        # Validate iterations
        if experiment.iterations < 1:
            errors.append("iterations must be >= 1")

        return errors

    @staticmethod
    def validate_all(experiments: list[ExperimentDefinition]) -> dict[str, list[str]]:
        """
        Validate multiple experiments.

        Args:
            experiments: List of ExperimentDefinition objects

        Returns:
            Dict mapping experiment_id to list of errors (missing keys for valid experiments)
        """
        results = {}
        for experiment in experiments:
            errors = ScenarioValidator.validate(experiment)
            if errors:
                results[experiment.experiment_id] = errors
        return results



