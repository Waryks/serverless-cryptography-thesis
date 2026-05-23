"""
Story 14: Experiment definition models for configurable scenario system.

This module defines the core data models for experiment configuration,
enabling reproducible, versionable, and self-describing experiments.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import hashlib
import json


class Algorithm(Enum):
    """Supported cryptographic algorithms."""
    HMAC_SHA256 = "HMAC_SHA256"
    RSA_PSS_SHA256 = "RSA_PSS_SHA256"
    ECDSA_P256_SHA256 = "ECDSA_P256_SHA256"


class PayloadSize(Enum):
    """Predefined payload sizes for workload variation."""
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"


class ColdStartMode(Enum):
    """Cold start execution modes for performance analysis."""
    NONE = "none"  # Warm invocations (reuse container)
    PER_ITERATION = "per_iteration"  # Reset between iterations
    PER_EXPERIMENT = "per_experiment"  # Reset before experiment starts
    IDLE_WAIT = "idle_wait"  # Simulate cold start via idle timeout


class CacheMode(Enum):
    """Cache configuration options."""
    DISABLED = "disabled"  # No caching
    ENABLED = "enabled"  # Caching enabled


class RotationMode(Enum):
    """Key rotation configuration."""
    CURRENT_ONLY = "current_only"  # Use only current key
    CURRENT_AND_PREVIOUS = "current_and_previous"  # Support key rotation with previous key


class ExecutionMode(Enum):
    """Execution concurrency modes."""
    SEQUENTIAL = "sequential"  # One invocation at a time
    CONCURRENT = "concurrent"  # Multiple invocations simultaneously


class ExpectedOutcome(Enum):
    """Expected outcome for scenario validation."""
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class ReplayDedupConfig:
    """Configuration for replay protection and deduplication."""
    replay_enabled: bool = True
    dedup_enabled: bool = True
    replay_window_ms: int = 300000  # 5 minutes default


@dataclass(frozen=True)
class CryptoConfig:
    """Cryptographic configuration for experiment."""
    algorithm: Algorithm
    cache_enabled: bool = False
    rotation_mode: RotationMode = RotationMode.CURRENT_ONLY


@dataclass(frozen=True)
class WorkloadConfig:
    """Workload definition for experiment."""
    payload_size: PayloadSize
    execution_mode: ExecutionMode = ExecutionMode.SEQUENTIAL


@dataclass(frozen=True)
class ColdStartConfig:
    """Cold start execution configuration."""
    mode: ColdStartMode
    idle_wait_seconds: float = 0.0


@dataclass(frozen=True)
class ExperimentDefinition:
    """
    Complete experiment definition combining all variations.

    Enables reproducible, versionable experiments that can be:
    - Versioned in git
    - Executed consistently across runs
    - Analyzed systematically in thesis evaluation
    - Combined into experiment matrices
    """

    # Identification
    experiment_id: str
    description: str

    # Scenario type
    scenario: str  # accepted, rejected, replay, duplicate, expired

    # Configuration
    crypto_config: CryptoConfig
    workload_config: WorkloadConfig
    cold_start_config: ColdStartConfig
    replay_dedup_config: ReplayDedupConfig

    # Execution
    iterations: int
    expected_outcome: ExpectedOutcome

    # Timing constraints
    completion_timeout_seconds: float = 8.0
    poll_interval_seconds: float = 0.25

    # Optional metadata
    key_id: Optional[str] = None
    tags: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert experiment to dictionary representation."""
        return {
            "experiment_id": self.experiment_id,
            "description": self.description,
            "scenario": self.scenario,
            "crypto_config": {
                "algorithm": self.crypto_config.algorithm.value,
                "cache_enabled": self.crypto_config.cache_enabled,
                "rotation_mode": self.crypto_config.rotation_mode.value,
            },
            "workload_config": {
                "payload_size": self.workload_config.payload_size.value,
                "execution_mode": self.workload_config.execution_mode.value,
            },
            "cold_start_config": {
                "mode": self.cold_start_config.mode.value,
                "idle_wait_seconds": self.cold_start_config.idle_wait_seconds,
            },
            "replay_dedup_config": {
                "replay_enabled": self.replay_dedup_config.replay_enabled,
                "dedup_enabled": self.replay_dedup_config.dedup_enabled,
                "replay_window_ms": self.replay_dedup_config.replay_window_ms,
            },
            "iterations": self.iterations,
            "expected_outcome": self.expected_outcome.value,
            "completion_timeout_seconds": self.completion_timeout_seconds,
            "poll_interval_seconds": self.poll_interval_seconds,
            "key_id": self.key_id,
            "tags": self.tags,
        }

    def compute_fingerprint(self) -> str:
        """
        Compute a deterministic fingerprint of experiment configuration.

        Used for:
        - Reproducibility verification
        - Comparing experiments across runs
        - Cache invalidation
        """
        config_json = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(config_json.encode()).hexdigest()[:12]

    def is_cold_start_scenario(self) -> bool:
        """Return True if this experiment involves cold start measurements."""
        return self.cold_start_config.mode != ColdStartMode.NONE

    def is_replay_scenario(self) -> bool:
        """Return True if this experiment tests replay protection."""
        return self.scenario == "replay"

    def is_dedup_scenario(self) -> bool:
        """Return True if this experiment tests deduplication."""
        return self.scenario in ("duplicate", "replay")


@dataclass
class ScenarioExecutionResult:
    """Result of a single scenario execution."""
    experiment_id: str
    iteration: int
    event_id: str
    latency_ms: float
    outcome: ExpectedOutcome
    is_cold_start: bool
    success: bool  # outcome matches expected_outcome
    metrics: dict = field(default_factory=dict)
    error: Optional[str] = None
    timestamp_ms: int = 0

