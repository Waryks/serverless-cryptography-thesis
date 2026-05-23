from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from benchmark.runner.scenario_runner import ScenarioExecutionRequest, ScenarioRunner

DEFAULT_KEY_IDS = {
    "HMAC_SHA256": "thesis/hmac/current",
    "RSA_PSS_SHA256": "thesis/rsa/current",
    "ECDSA_P256_SHA256": "thesis/ecdsa/current",
}


@dataclass(frozen=True)
class ExperimentConfig:
    name: str
    scenario: str
    algorithm: str
    payload_size: str
    policy_mode: str
    iterations: int
    expected_outcome: str
    key_id: str | None = None
    replay_window_ms: int = 300000
    wait_for_completion: bool = True
    completion_timeout_seconds: float = 8.0
    poll_seconds: float = 0.25
    cold_start_mode: str = "none"
    idle_wait_seconds: float = 0.0
    reset_between_iterations: bool = False


class ExperimentRunner:
    def __init__(self, scenario_runner: ScenarioRunner, reset_script: Path | None) -> None:
        self._scenario_runner = scenario_runner
        self._reset_script = reset_script

    def run_experiment(self, config: ExperimentConfig) -> list[dict]:
        rows: list[dict] = []

        if config.cold_start_mode == "per_experiment":
            self._reset_environment()

        for iteration in range(1, config.iterations + 1):
            if config.reset_between_iterations or config.cold_start_mode == "per_iteration":
                self._reset_environment()
            if config.cold_start_mode == "idle_wait" and config.idle_wait_seconds > 0:
                time.sleep(config.idle_wait_seconds)

            key_id = config.key_id or DEFAULT_KEY_IDS[config.algorithm]
            row = self._scenario_runner.run(
                ScenarioExecutionRequest(
                    scenario=config.scenario,
                    algorithm=config.algorithm,
                    key_id=key_id,
                    payload_size=config.payload_size,
                    expected_outcome=config.expected_outcome,
                    replay_window_ms=config.replay_window_ms,
                    iteration=iteration,
                    policy_mode=config.policy_mode,
                    wait_for_completion=config.wait_for_completion,
                    completion_timeout_seconds=config.completion_timeout_seconds,
                    poll_seconds=config.poll_seconds,
                )
            )
            row["experiment"] = config.name
            rows.append(row)
            print(
                "iteration=%s scenario=%s eventId=%s latencyMs=%s outcome=%s"
                % (
                    iteration,
                    config.scenario,
                    row["event_id"],
                    row["producer_latency_ms"],
                    row["final_outcome"],
                )
            )

        return rows

    def _reset_environment(self) -> None:
        if not self._reset_script:
            return
        subprocess.run([sys.executable, str(self._reset_script)], check=True)

