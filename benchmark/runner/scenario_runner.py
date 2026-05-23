from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from benchmark.collectors.result_collector import ResultCollector
from benchmark.scenarios.accepted_flow import build_event
from benchmark.scenarios.duplicate_scenario import build_duplicate_events
from benchmark.scenarios.rejected_flow import build_expired_event
from benchmark.scenarios.replay_scenario import build_replay_events


@dataclass(frozen=True)
class ScenarioExecutionRequest:
    scenario: str
    algorithm: str
    key_id: str
    payload_size: str
    expected_outcome: str
    replay_window_ms: int
    iteration: int
    policy_mode: str
    wait_for_completion: bool
    completion_timeout_seconds: float
    poll_seconds: float


class ScenarioRunner:
    def __init__(self, lambda_client: Any, producer_function_name: str, result_collector: ResultCollector) -> None:
        self._lambda = lambda_client
        self._producer_function_name = producer_function_name
        self._collector = result_collector

    def run(self, request: ScenarioExecutionRequest) -> dict:
        if request.scenario == "accepted":
            payload = build_event(request.algorithm, request.key_id, request.payload_size)
            return self._invoke_once(payload, request)

        if request.scenario == "expired":
            payload = build_expired_event(
                request.algorithm,
                request.key_id,
                request.payload_size,
                request.replay_window_ms,
            )
            return self._invoke_once(payload, request)

        if request.scenario == "duplicate":
            first, second = build_duplicate_events(request.algorithm, request.key_id, request.payload_size)
            return self._invoke_twice(first, second, request)

        if request.scenario == "replay":
            first, second = build_replay_events(request.algorithm, request.key_id, request.payload_size)
            return self._invoke_twice(first, second, request)

        raise ValueError(f"Unsupported scenario: {request.scenario}")

    def _invoke_once(self, payload: dict, request: ScenarioExecutionRequest) -> dict:
        invoke_start_ms = int(time.time() * 1000)
        producer_response = self._invoke_producer(payload)
        invoke_end_ms = int(time.time() * 1000)

        event_id = payload["content"]["eventId"]
        completion = None
        if request.wait_for_completion:
            completion = self._collector.wait_for_outcome(
                expected_outcome=request.expected_outcome,
                event_id=event_id,
                timeout_seconds=request.completion_timeout_seconds,
                poll_seconds=request.poll_seconds,
            )

        return _build_row(
            request=request,
            event_id=event_id,
            invoke_start_ms=invoke_start_ms,
            invoke_end_ms=invoke_end_ms,
            producer_response=producer_response,
            completion=completion,
            invocation_count=1,
        )

    def _invoke_twice(self, first_payload: dict, second_payload: dict, request: ScenarioExecutionRequest) -> dict:
        _ = self._invoke_producer(first_payload)
        invoke_start_ms = int(time.time() * 1000)
        producer_response = self._invoke_producer(second_payload)
        invoke_end_ms = int(time.time() * 1000)

        event_id = second_payload["content"]["eventId"]
        completion = None
        if request.wait_for_completion:
            completion = self._collector.wait_for_outcome(
                expected_outcome=request.expected_outcome,
                event_id=event_id,
                timeout_seconds=request.completion_timeout_seconds,
                poll_seconds=request.poll_seconds,
            )

        return _build_row(
            request=request,
            event_id=event_id,
            invoke_start_ms=invoke_start_ms,
            invoke_end_ms=invoke_end_ms,
            producer_response=producer_response,
            completion=completion,
            invocation_count=2,
        )

    def _invoke_producer(self, payload: dict) -> dict:
        response = self._lambda.invoke(
            FunctionName=self._producer_function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
        payload_bytes = response["Payload"].read()
        if response.get("FunctionError"):
            raise RuntimeError(payload_bytes.decode("utf-8"))

        body = json.loads(payload_bytes)
        if isinstance(body, str):
            return json.loads(body)
        return body


def _build_row(
    request: ScenarioExecutionRequest,
    event_id: str,
    invoke_start_ms: int,
    invoke_end_ms: int,
    producer_response: dict,
    completion: Any,
    invocation_count: int,
) -> dict:
    completion_ms = completion.completed_at_ms if completion else None
    end_to_end_latency = None
    if completion_ms is not None:
        end_to_end_latency = max(0.0, float(completion_ms - invoke_start_ms))

    final_outcome = completion.outcome if completion else "UNKNOWN"
    matched_expected = completion.matched if completion else False

    return {
        "scenario": request.scenario,
        "iteration": request.iteration,
        "event_id": event_id,
        "algorithm": request.algorithm,
        "key_id": request.key_id,
        "payload_size": request.payload_size,
        "policy_mode": request.policy_mode,
        "expected_outcome": request.expected_outcome,
        "final_outcome": final_outcome,
        "matched_expected_outcome": matched_expected,
        "producer_latency_ms": float(producer_response.get("durationMs", invoke_end_ms - invoke_start_ms)),
        "end_to_end_latency_ms": end_to_end_latency,
        "producer_cold_start": bool(producer_response.get("coldStart", False)),
        "producer_event_id": producer_response.get("eventId"),
        "invocation_count": invocation_count,
        "invoke_started_at_ms": invoke_start_ms,
        "invoke_ended_at_ms": invoke_end_ms,
    }

