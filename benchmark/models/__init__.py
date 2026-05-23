"""
Story 14: Experiment Configuration and Scenario System

Provides configurable experiment and scenario subsystem for reproducible
benchmark runs using predefined configurations.
"""

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
    ScenarioExecutionResult,
)
from benchmark.models.scenario_loader import (
    ScenarioLoader,
    ScenarioValidator,
)
from benchmark.models.scenario_executor import (
    ScenarioExecutor,
    ScenarioExecutionContext,
)
from benchmark.models.result_validator import (
    ResultValidator,
    ClassifiedResult,
    ResultClassification,
)

__all__ = [
    # Enums and types
    "Algorithm",
    "PayloadSize",
    "ColdStartMode",
    "CacheMode",
    "RotationMode",
    "ExecutionMode",
    "ExpectedOutcome",

    # Configuration classes
    "ReplayDedupConfig",
    "CryptoConfig",
    "WorkloadConfig",
    "ColdStartConfig",
    "ExperimentDefinition",
    "ScenarioExecutionResult",

    # Loader and validator
    "ScenarioLoader",
    "ScenarioValidator",

    # Executor
    "ScenarioExecutor",
    "ScenarioExecutionContext",

    # Result validation
    "ResultValidator",
    "ClassifiedResult",
    "ResultClassification",
]



