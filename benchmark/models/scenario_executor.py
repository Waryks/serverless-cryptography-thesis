"""
Story 14: Scenario executor for orchestrating experiment execution.

Applies experiment configuration, generates workloads, executes scenarios,
and validates outcomes.
"""

from __future__ import annotations

import logging
from typing import Optional
from datetime import datetime

from benchmark.models.experiment_definition import (
    ExperimentDefinition,
    ExpectedOutcome,
    ScenarioExecutionResult,
)
from benchmark.runner.scenario_runner import ScenarioRunner


logger = logging.getLogger(__name__)


class ScenarioExecutor:
    """
    Executes scenarios based on experiment configuration.

    Responsibilities:
    - Apply experiment configuration to scenario execution
    - Generate appropriately-sized workloads
    - Execute iterations with configured cold start behavior
    - Validate actual outcomes against expected outcomes
    - Collect metrics and results
    """

    def __init__(self, scenario_runner: ScenarioRunner):
        """
        Initialize scenario executor.

        Args:
            scenario_runner: ScenarioRunner instance for executing scenarios
        """
        self.scenario_runner = scenario_runner

    def execute(self, experiment: ExperimentDefinition) -> list[ScenarioExecutionResult]:
        """
        Execute experiment scenario with configured variations.

        Args:
            experiment: ExperimentDefinition specifying how to execute

        Returns:
            List of ScenarioExecutionResult objects for each iteration
        """
        results = []
        start_time_ms = datetime.now().timestamp() * 1000

        logger.info(
            f"Starting experiment '{experiment.experiment_id}' "
            f"(scenario={experiment.scenario}, "
            f"iterations={experiment.iterations}, "
            f"algorithm={experiment.crypto_config.algorithm.value}, "
            f"fingerprint={experiment.compute_fingerprint()})"
        )

        for iteration in range(experiment.iterations):
            try:
                result = self._execute_iteration(experiment, iteration)
                results.append(result)

                # Log with experiment metadata
                logger.info(
                    f"experiment={experiment.experiment_id} "
                    f"iteration={iteration} "
                    f"latencyMs={result.latency_ms:.1f} "
                    f"outcome={result.outcome.value} "
                    f"success={result.success} "
                    f"coldStart={result.is_cold_start}"
                )

            except Exception as e:
                logger.error(
                    f"Error executing iteration {iteration} of {experiment.experiment_id}: {e}",
                    exc_info=True
                )
                # Record failure but continue with other iterations
                result = ScenarioExecutionResult(
                    experiment_id=experiment.experiment_id,
                    iteration=iteration,
                    event_id="unknown",
                    latency_ms=0.0,
                    outcome=ExpectedOutcome.REJECTED,
                    is_cold_start=False,
                    success=False,
                    error=str(e),
                )
                results.append(result)

        end_time_ms = datetime.now().timestamp() * 1000
        duration_ms = end_time_ms - start_time_ms

        logger.info(
            f"Completed experiment '{experiment.experiment_id}' "
            f"in {duration_ms:.0f}ms with {len(results)} results"
        )

        return results

    def _execute_iteration(
        self, experiment: ExperimentDefinition, iteration: int
    ) -> ScenarioExecutionResult:
        """
        Execute single iteration of scenario.

        Args:
            experiment: ExperimentDefinition
            iteration: Iteration number (0-based)

        Returns:
            ScenarioExecutionResult with timing and outcome
        """

        # Determine if this iteration is a cold start
        is_cold_start = self._should_be_cold_start(experiment, iteration)

        # Generate event based on scenario type
        event = self._generate_event(experiment, iteration)

        # Execute scenario with timing
        start_time_ms = datetime.now().timestamp() * 1000

        result = self.scenario_runner.run(
            scenario_name=experiment.scenario,
            event=event,
            algorithm=experiment.crypto_config.algorithm.value,
            payload_size=experiment.workload_config.payload_size.value,
            expected_outcome=experiment.expected_outcome.value,
        )

        end_time_ms = datetime.now().timestamp() * 1000
        latency_ms = end_time_ms - start_time_ms

        # Validate outcome
        success = str(result.get("outcome", "")) == experiment.expected_outcome.value

        return ScenarioExecutionResult(
            experiment_id=experiment.experiment_id,
            iteration=iteration,
            event_id=event.get("eventId", "unknown"),
            latency_ms=latency_ms,
            outcome=ExpectedOutcome(result.get("outcome", "REJECTED")),
            is_cold_start=is_cold_start,
            success=success,
            metrics=result.get("metrics", {}),
            timestamp_ms=int(end_time_ms),
        )

    def _should_be_cold_start(self, experiment: ExperimentDefinition, iteration: int) -> bool:
        """Determine if iteration should be marked as cold start."""
        from benchmark.models.experiment_definition import ColdStartMode

        mode = experiment.cold_start_config.mode

        if mode == ColdStartMode.NONE:
            return False
        elif mode == ColdStartMode.PER_ITERATION:
            return True  # Every iteration is marked cold
        elif mode == ColdStartMode.PER_EXPERIMENT:
            return iteration == 0  # Only first iteration is cold
        elif mode == ColdStartMode.IDLE_WAIT:
            # In real execution, this would trigger an idle period
            return iteration == 0

        return False

    def _generate_event(
        self, experiment: ExperimentDefinition, iteration: int
    ) -> dict:
        """
        Generate event appropriate for scenario and iteration.

        Args:
            experiment: ExperimentDefinition
            iteration: Iteration number

        Returns:
            Generated event dict ready for Lambda invocation
        """
        # Use scenario runner's event generation
        # The actual event generation is delegated to scenario-specific generators
        # This method ensures configuration is applied consistently

        event = {}

        # These will be populated by scenario-specific generators
        # but we apply configuration constraints here

        if experiment.is_replay_scenario():
            # Replay scenarios should use same eventId
            event["reuseEventId"] = True

        if experiment.is_dedup_scenario() and iteration > 0:
            # Dedup scenarios should repeat eventId
            event["reuseEventId"] = True

        return event


class ScenarioExecutionContext:
    """
    Execution context for a scenario run.

    Provides configuration and environment information to scenario execution.
    """

    def __init__(
        self,
        experiment: ExperimentDefinition,
        iteration: int,
        event_id: str,
    ):
        """Initialize execution context."""
        self.experiment = experiment
        self.iteration = iteration
        self.event_id = event_id
        self.start_time_ms = datetime.now().timestamp() * 1000
        self.end_time_ms: Optional[float] = None
        self.metadata = {
            "experiment_id": experiment.experiment_id,
            "fingerprint": experiment.compute_fingerprint(),
            "algorithm": experiment.crypto_config.algorithm.value,
            "payload_size": experiment.workload_config.payload_size.value,
            "cold_start_mode": experiment.cold_start_config.mode.value,
            "cache_enabled": experiment.crypto_config.cache_enabled,
            "rotation_mode": experiment.crypto_config.rotation_mode.value,
            "replay_enabled": experiment.replay_dedup_config.replay_enabled,
            "dedup_enabled": experiment.replay_dedup_config.dedup_enabled,
        }

    def finish(self):
        """Mark context as finished."""
        self.end_time_ms = datetime.now().timestamp() * 1000

    def get_duration_ms(self) -> float:
        """Get execution duration in milliseconds."""
        if self.end_time_ms is None:
            return 0.0
        return self.end_time_ms - self.start_time_ms

    def to_json_dict(self) -> dict:
        """Convert context to JSON-serializable dict."""
        return {
            "experimentId": self.experiment.experiment_id,
            "fingerprint": self.experiment.compute_fingerprint(),
            "iteration": self.iteration,
            "eventId": self.event_id,
            "durationMs": self.get_duration_ms(),
            "metadata": self.metadata,
        }


