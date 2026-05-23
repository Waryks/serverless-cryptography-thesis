from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import boto3
import yaml
from botocore.config import Config as BotoConfig

from benchmark.collectors.audit_collector import AuditCollector
from benchmark.collectors.ledger_collector import LedgerCollector
from benchmark.collectors.result_collector import ResultCollector
from benchmark.metrics.latency_metrics import build_metrics
from benchmark.output.csv_writer import write_csv
from benchmark.output.json_writer import write_json
from benchmark.runner.experiment_runner import ExperimentConfig, ExperimentRunner
from benchmark.runner.scenario_runner import ScenarioRunner


@dataclass(frozen=True)
class RuntimeConfig:
    localstack_endpoint: str
    aws_region: str
    producer_function_name: str
    ledger_table: str
    audit_table: str
    output_dir: Path
    reset_script: Path | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark experiment orchestrator")
    parser.add_argument(
        "--config",
        default="benchmark/config/experiment_config.yaml",
        help="Path to experiment YAML config",
    )
    parser.add_argument(
        "--output-dir",
        default="benchmark/output/results",
        help="Directory for CSV/JSON output",
    )
    parser.add_argument(
        "--localstack-endpoint",
        default="http://localhost:4566",
        help="LocalStack endpoint",
    )
    parser.add_argument("--region", default="eu-central-1", help="AWS region")
    parser.add_argument(
        "--producer-function",
        default="thesis-producer",
        help="Producer Lambda function name",
    )
    parser.add_argument("--ledger-table", default="thesis_ledger", help="Ledger table")
    parser.add_argument("--audit-table", default="thesis_audit", help="Audit table")
    parser.add_argument(
        "--reset-script",
        default="localstack/reset.py",
        help="Path to localstack reset script (set to empty to disable)",
    )
    parser.add_argument(
        "--experiment",
        default="",
        help="Run only one experiment by name",
    )
    return parser.parse_args()


def _aws_client(service_name: str, runtime: RuntimeConfig):
    return boto3.client(
        service_name,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name=runtime.aws_region,
        endpoint_url=runtime.localstack_endpoint,
        config=BotoConfig(read_timeout=120, connect_timeout=10, retries={"max_attempts": 0}),
    )


def _load_experiments(config_path: Path) -> list[ExperimentConfig]:
    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    experiments = []
    for item in data.get("experiments", []):
        experiments.append(
            ExperimentConfig(
                name=item["name"],
                scenario=item["scenario"],
                algorithm=item["algorithm"],
                payload_size=item.get("payload_size", "small"),
                policy_mode=item.get("policy_mode", "default"),
                iterations=int(item.get("iterations", 1)),
                expected_outcome=item.get("expected_outcome", "ACCEPTED"),
                key_id=item.get("key_id"),
                replay_window_ms=int(item.get("replay_window_ms", 300000)),
                wait_for_completion=bool(item.get("wait_for_completion", True)),
                completion_timeout_seconds=float(item.get("completion_timeout_seconds", 8.0)),
                poll_seconds=float(item.get("poll_seconds", 0.25)),
                cold_start_mode=item.get("cold_start_mode", "none"),
                idle_wait_seconds=float(item.get("idle_wait_seconds", 0.0)),
                reset_between_iterations=bool(item.get("reset_between_iterations", False)),
            )
        )
    return experiments


def main() -> None:
    args = parse_args()
    runtime = RuntimeConfig(
        localstack_endpoint=args.localstack_endpoint,
        aws_region=args.region,
        producer_function_name=args.producer_function,
        ledger_table=args.ledger_table,
        audit_table=args.audit_table,
        output_dir=Path(args.output_dir),
        reset_script=Path(args.reset_script) if args.reset_script else None,
    )

    lambda_client = _aws_client("lambda", runtime)
    dynamodb_client = _aws_client("dynamodb", runtime)

    collector = ResultCollector(
        ledger_collector=LedgerCollector(dynamodb_client, runtime.ledger_table),
        audit_collector=AuditCollector(dynamodb_client, runtime.audit_table),
    )
    scenario_runner = ScenarioRunner(lambda_client, runtime.producer_function_name, collector)
    experiment_runner = ExperimentRunner(scenario_runner, runtime.reset_script)

    experiments = _load_experiments(Path(args.config))
    if args.experiment:
        experiments = [e for e in experiments if e.name == args.experiment]

    if not experiments:
        raise SystemExit("No experiments selected")

    all_rows: list[dict] = []
    for experiment in experiments:
        print(f"running experiment={experiment.name} scenario={experiment.scenario}")
        all_rows.extend(experiment_runner.run_experiment(experiment))

    metrics = build_metrics(all_rows)
    payload = {
        "runtime": {
            "localstack_endpoint": runtime.localstack_endpoint,
            "aws_region": runtime.aws_region,
            "producer_function_name": runtime.producer_function_name,
            "ledger_table": runtime.ledger_table,
            "audit_table": runtime.audit_table,
        },
        "metrics": metrics,
        "results": all_rows,
    }

    csv_path = runtime.output_dir / "benchmark_results.csv"
    json_path = runtime.output_dir / "benchmark_results.json"

    write_csv(csv_path, all_rows)
    write_json(json_path, payload)

    print(f"wrote csv={csv_path}")
    print(f"wrote json={json_path}")


if __name__ == "__main__":
    main()

