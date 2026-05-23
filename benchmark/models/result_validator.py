"""
Story 14: Scenario result classification and validation.

Classifies and validates scenario execution results against expectations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from benchmark.models.experiment_definition import (
    ExperimentDefinition,
    ScenarioExecutionResult,
    ExpectedOutcome,
)


class ResultClassification(Enum):
    """Classification of scenario execution result."""
    SUCCESS = "success"  # outcome matches expected_outcome
    OUTCOME_MISMATCH = "outcome_mismatch"  # outcome differs from expected
    EXECUTION_ERROR = "execution_error"  # error during execution
    TIMEOUT = "timeout"  # execution exceeded timeout


@dataclass
class ClassifiedResult:
    """Classified and validated scenario result."""

    result: ScenarioExecutionResult
    classification: ResultClassification

    def is_valid(self) -> bool:
        """Return True if execution was valid (success or expected failure)."""
        return self.classification == ResultClassification.SUCCESS

    def is_error(self) -> bool:
        """Return True if execution encountered an error."""
        return self.classification in (
            ResultClassification.EXECUTION_ERROR,
            ResultClassification.TIMEOUT,
        )

    def is_outcome_mismatch(self) -> bool:
        """Return True if outcome doesn't match expectation."""
        return self.classification == ResultClassification.OUTCOME_MISMATCH


class ResultValidator:
    """Validates and classifies scenario execution results."""

    @staticmethod
    def classify(
        result: ScenarioExecutionResult,
        experiment: ExperimentDefinition,
    ) -> ClassifiedResult:
        """
        Classify scenario execution result.

        Args:
            result: ScenarioExecutionResult from execution
            experiment: ExperimentDefinition that was executed

        Returns:
            ClassifiedResult with classification and validation status
        """

        # Check for execution errors
        if result.error:
            return ClassifiedResult(
                result=result,
                classification=ResultClassification.EXECUTION_ERROR,
            )

        # Check for outcome match
        if result.outcome == experiment.expected_outcome:
            return ClassifiedResult(
                result=result,
                classification=ResultClassification.SUCCESS,
            )

        # Outcome mismatch
        return ClassifiedResult(
            result=result,
            classification=ResultClassification.OUTCOME_MISMATCH,
        )

    @staticmethod
    def classify_batch(
        results: list[ScenarioExecutionResult],
        experiment: ExperimentDefinition,
    ) -> list[ClassifiedResult]:
        """
        Classify multiple results.

        Args:
            results: List of ScenarioExecutionResult objects
            experiment: ExperimentDefinition that was executed

        Returns:
            List of ClassifiedResult objects
        """
        return [
            ResultValidator.classify(result, experiment)
            for result in results
        ]

    @staticmethod
    def summarize(classified_results: list[ClassifiedResult]) -> dict:
        """
        Summarize classification results.

        Args:
            classified_results: List of ClassifiedResult objects

        Returns:
            Dict with summary statistics
        """
        total = len(classified_results)
        successes = sum(1 for r in classified_results if r.classification == ResultClassification.SUCCESS)
        mismatches = sum(1 for r in classified_results if r.classification == ResultClassification.OUTCOME_MISMATCH)
        errors = sum(1 for r in classified_results if r.classification == ResultClassification.EXECUTION_ERROR)

        avg_latency = sum(r.result.latency_ms for r in classified_results) / total if total > 0 else 0.0

        return {
            "total": total,
            "successes": successes,
            "mismatches": mismatches,
            "errors": errors,
            "success_rate": successes / total if total > 0 else 0.0,
            "avg_latency_ms": avg_latency,
        }

