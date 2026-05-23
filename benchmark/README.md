# Benchmark Runner

Comprehensive benchmark orchestration framework for automated experiment execution, event generation, Lambda invocation, and result collection with reproducible benchmark results.

**Status**: Implemented

Exercises the full pipeline: **Producer Lambda → Validation Lambda → Accepted/Rejected routing → Persistence/Audit Lambdas → DynamoDB**

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r benchmark/requirements.txt

# 2. Run the model verification check
python3 benchmark/verify_models.py

# 3. Run a benchmark experiment
python3 benchmark/runner/benchmark_runner.py --experiment smoke_test

# 4. Run full experiment suite (29 experiments)
python3 benchmark/runner/benchmark_runner.py

# 5. View results
cat benchmark/output/results/benchmark_results.csv
cat benchmark/output/results/benchmark_results.json
```

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.11+ |
| LocalStack | Running (SQS, DynamoDB, Lambda) |
| Producer Lambda | Deployed (`thesis-producer`) |
| Validation Lambda | Deployed and subscribed to the ingress queue |
| Persistence Lambda | Deployed and subscribed to the accepted queue |
| Audit Lambda | Deployed and subscribed to the rejected queue |

### LocalStack Setup

```bash
# Start LocalStack with required services
docker run -d -p 4566:4566 \
  -e SERVICES=sqs,dynamodb,lambda,logs,secretsmanager \
  localstack/localstack

# Provision infrastructure
python3 localstack/bootstrap.py
```

### Install Dependencies

```bash
pip install -r benchmark/requirements.txt
```

---

## Benchmark Runner Overview

The benchmark runner includes:

- **18 Python modules** across 8 subsystems
- **29 pre-configured experiments** covering all dimensions
- **YAML-based configuration** for easy customization
- **Multiple test scenarios**: accepted, rejected, replay, duplicate, expired
- **Cold-start support**: Multiple modes (per_iteration, per_experiment, idle_wait, none)
- **Comprehensive metrics**: Producer + end-to-end latency, percentiles (p50/p95/p99), success rates
- **CSV & JSON export**: Analysis-ready output formats

---

## Usage

### Run All Experiments

```bash
python3 benchmark/runner/benchmark_runner.py
```

Generates:
- `benchmark/output/results/benchmark_results.csv` — Tabular results
- `benchmark/output/results/benchmark_results.json` — Structured report with metrics

### Run Single Experiment

```bash
python3 benchmark/runner/benchmark_runner.py --experiment smoke_test
python3 benchmark/runner/benchmark_runner.py --experiment baseline_hmac_cold
python3 benchmark/runner/benchmark_runner.py --experiment warm_rsa_50
```

### Custom Configuration

```bash
python3 benchmark/runner/benchmark_runner.py \
  --config custom_config.yaml \
  --output-dir /tmp/results \
  --localstack-endpoint http://localhost:4566 \
  --region eu-central-1
```

---

## 29 Experiments (Organized by Type)

### Cold-Start Baselines (3)
Measures maximum cold-start overhead per algorithm
- `baseline_hmac_cold` — HMAC with 5 cold iterations
- `baseline_rsa_cold` — RSA with 5 cold iterations
- `baseline_ecdsa_cold` — ECDSA with 5 cold iterations

### Warm Runs (3)
Establishes warm-state performance baseline
- `warm_hmac_50` — 50 sequential HMAC invocations
- `warm_rsa_50` — 50 sequential RSA invocations
- `warm_ecdsa_50` — 50 sequential ECDSA invocations

### Payload Variation (3)
Measures crypto overhead across payload sizes
- `payload_hmac_small` — Small payloads (2 fields)
- `payload_hmac_medium` — Medium payloads (8 fields)
- `payload_hmac_large` — Large payloads (20 fields)

### Replay Protection (3)
Validates duplicate eventId detection
- `replay_hmac` — HMAC replay attack
- `replay_rsa` — RSA replay attack
- `replay_ecdsa` — ECDSA replay attack

### Deduplication (3)
Validates dedup store functionality
- `duplicate_hmac` — HMAC dedup detection
- `duplicate_rsa` — RSA dedup detection
- `duplicate_ecdsa` — ECDSA dedup detection

### Expiration/Replay Window (3)
Validates replay window enforcement
- `expired_hmac` — HMAC outside replay window
- `expired_rsa` — RSA outside replay window
- `expired_ecdsa` — ECDSA outside replay window

### Validation (1)
Quick end-to-end check
- `smoke_test` — Single HMAC invocation

---

## Output Formats

### CSV Output (`benchmark_results.csv`)

Tabular format with one row per Lambda invocation:

```
scenario,iteration,event_id,algorithm,key_id,payload_size,...
producer_latency_ms,end_to_end_latency_ms,producer_cold_start,final_outcome,...
```

Columns include:
- Scenario, iteration, event_id
- Algorithm, key_id, payload_size, policy_mode
- Expected/final outcomes
- Producer and end-to-end latencies
- Cold-start flag, invocation count
- Timestamps for analysis

### JSON Output (`benchmark_results.json`)

Structured report with aggregated metrics:

```json
{
  "runtime": {
    "endpoint": "http://localhost:4566",
    "region": "eu-central-1",
    "function_names": ["thesis-producer", "thesis-validation", "thesis-persistence", "thesis-audit"],
    "table_names": ["thesis_ledger", "thesis_dedup", "thesis_audit"]
  },
  "metrics": {
    "producer_latency_ms": { "count": 0, "min": 0, "max": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0 },
    "end_to_end_latency_ms": { "count": 0, "min": 0, "max": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0 },
    "outcomes": { "total": 0, "success_rate": 0, "rejection_rate": 0 }
  },
  "results": []
}
```

---

## Architecture

### Core Modules

**Runner (Orchestration)**
- `benchmark_runner.py` — Entry point, CLI, result aggregation
- `experiment_runner.py` — Experiment orchestration, cold-start modes
- `scenario_runner.py` — Scenario execution, timing measurement

**Generators (Event Generation)**
- `event_generator.py` — Random event builder
- `payload_generator.py` — Variable-sized payloads
- `random_data.py` — Randomization utilities

**Scenarios (Test Cases)**
- `accepted_flow.py` — Valid events
- `rejected_flow.py` — Expired events
- `duplicate_scenario.py` — Duplicate eventId
- `replay_scenario.py` — Replay attacks

**Collectors (Result Collection)**
- `result_collector.py` — Outcome routing
- `ledger_collector.py` — Poll `thesis_ledger`
- `audit_collector.py` — Poll `thesis_audit`

**Metrics (Statistics)**
- `latency_metrics.py` — Aggregation
- `statistics.py` — Computations
- `percentile_metrics.py` — Percentile calculation

**Output (Exporters)**
- `csv_writer.py` — CSV export
- `json_writer.py` — JSON export

### Configuration

- `config/experiment_config.yaml` — 29 pre-configured experiments

For LocalStack provisioning, reset, and smoke tests, see `localstack/README.md`.

---

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Cold-start baseline (5 iterations) | ~2-3 minutes |
| Warm runs (50 iterations) | ~1-2 minutes |
| Full suite (29 experiments) | ~45-60 minutes |
| Timing precision | Millisecond granularity |

---

## Documentation

Implementation details are documented in `docs/benchmark.md`:

- **README.md** — Main benchmark usage guide
- **docs/benchmark.md** — Implementation overview and component summary
- **verify_models.py** — Lightweight model verification script

Start with **README.md** in the benchmark directory.

---

## Supported Algorithms

- `HMAC_SHA256` — Fast symmetric algorithm
- `RSA_PSS_SHA256` — Slow asymmetric algorithm
- `ECDSA_P256_SHA256` — Medium asymmetric algorithm

---

## Cold-Start Modes

- `none` — Warm invocations (reuse container)
- `per_iteration` — Reset between iterations
- `per_experiment` — Reset before experiment starts
- `idle_wait` — Simulate cold start via idle timeout

---

## Integration with Replay Protection and Deduplication

The benchmark suite exercises the validation-lambda security mechanisms for
deduplication and replay protection.

The benchmark scenarios validate:
- ✅ Replay detection (duplicate eventId)
- ✅ Dedup prevention (same eventId)
- ✅ Expiration enforcement (outside replay window)
- ✅ Accepted flow (valid events)

---

## Benchmark Capabilities ✅

1. ✅ Benchmark runner exists
2. ✅ Can invoke Producer Lambda
3. ✅ Generate events dynamically
4. ✅ Support configurable experiments
5. ✅ Wait for ledger completion
6. ✅ Wait for audit completion
7. ✅ Collect latency metrics
8. ✅ Export CSV and JSON results
9. ✅ Support accepted/rejected scenarios
10. ✅ Support cold and warm experiments

---

## Dependencies

All in `benchmark/requirements.txt`:

```
boto3>=1.34.0          # AWS SDK
botocore>=1.34.0       # AWS service models
cryptography>=42.0.0   # Cryptographic operations
PyYAML>=6.0            # Configuration parsing
```

---

## Implementation Summary

The benchmark runner provides:

- event generation and Lambda invocation
- accepted, rejected, replay, duplicate, and expired-event scenarios
- cold and warm execution modes
- latency and outcome collection
- CSV and JSON result export

All modules are organized by responsibility and documented in the sections above.
