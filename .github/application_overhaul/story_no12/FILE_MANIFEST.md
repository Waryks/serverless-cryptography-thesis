# Story 12 Implementation — File Manifest and Architecture

## Project Structure

```
benchmark/
├── __init__.py
├── README.md                          # Existing benchmark documentation
├── requirements.txt                   # Dependencies (updated with PyYAML)
├── run_benchmark.py                   # Existing benchmark runner (legacy)
├── run_attacks.py                     # Existing attack verification script
│
├── runner/                            # Core Orchestration
│   ├── __init__.py
│   ├── benchmark_runner.py            # ENTRY POINT - Main CLI orchestrator
│   ├── experiment_runner.py           # Experiment orchestration with cold-start
│   └── scenario_runner.py             # Scenario execution and timing
│
├── generators/                        # Event and Payload Generation
│   ├── __init__.py
│   ├── event_generator.py             # Event builder with EventBuildOptions
│   ├── payload_generator.py           # Variable-sized payload generation
│   └── random_data.py                 # Randomization utilities
│
├── scenarios/                         # Test Scenario Implementations
│   ├── __init__.py
│   ├── accepted_flow.py               # Valid event scenario
│   ├── rejected_flow.py               # Expired event scenario
│   ├── duplicate_scenario.py          # Duplicate eventId scenario
│   └── replay_scenario.py             # Replay attack scenario
│
├── collectors/                        # Result Collection from DynamoDB
│   ├── __init__.py
│   ├── result_collector.py            # Outcome router (ledger/audit)
│   ├── ledger_collector.py            # Poll thesis_ledger table
│   └── audit_collector.py             # Poll thesis_audit table
│
├── metrics/                           # Statistics and Metrics
│   ├── __init__.py
│   ├── latency_metrics.py             # Metrics aggregation
│   ├── statistics.py                  # Statistical computations
│   └── percentile_metrics.py          # Percentile calculations
│
├── output/                            # Result Exporters
│   ├── __init__.py
│   ├── csv_writer.py                  # Export results as CSV
│   └── json_writer.py                 # Export results as JSON
│
├── config/                            # Configuration (NEW)
│   └── experiment_config.yaml         # 29 pre-configured experiments
│
└── output/results/                    # Generated Output
    ├── benchmark_results.csv          # Result rows in tabular format
    └── benchmark_results.json         # Comprehensive report with metrics
```

## File Descriptions

### Entry Point

**`benchmark/runner/benchmark_runner.py`** (167 lines)
- CLI argument parser for configuration, output directory, endpoint, region
- Loads YAML experiments from `experiment_config.yaml`
- Manages AWS Lambda and DynamoDB clients for LocalStack
- Orchestrates experiment execution
- Aggregates results and computes metrics
- Exports CSV and JSON outputs

### Core Orchestration

**`benchmark/runner/experiment_runner.py`** (90 lines)
- `ExperimentConfig` dataclass: Defines all experiment parameters
  - Name, scenario, algorithm, payload size
  - Iterations, expected outcome
  - Cold-start modes, timing parameters
- Handles environment resets between iterations
- Supports multiple cold-start strategies
- Calls `ScenarioRunner` for each iteration

**`benchmark/runner/scenario_runner.py`** (164 lines)
- `ScenarioExecutionRequest` dataclass: Captures scenario context
- Routes to appropriate scenario builder (accepted/expired/duplicate/replay)
- Measures producer invocation latency
- Optionally waits for end-to-end completion via result collectors
- Builds comprehensive result row with all metrics

### Event Generation

**`benchmark/generators/event_generator.py`** (34 lines)
- `EventBuildOptions` dataclass: Event parameters
- `generate_unsigned_event()`: Builds valid event structure
- Generates random eventId, timestamps
- Incorporates algorithm, keyId, payload
- Event ready for Producer Lambda

**`benchmark/generators/payload_generator.py`** (35 lines)
- `generate_payload()`: Creates variable-sized payloads
- `small`: 2 fields, ~48 chars
- `medium`: 8 fields, ~256 chars
- `large`: 20 fields, ~1024 chars
- Returns nested JSON with realistic structure

**`benchmark/generators/random_data.py`** (24 lines)
- `random_uuid()`: UUID v4 strings
- `random_string(length)`: Alphanumeric random strings
- `random_float()`: Decimal 0-10000
- `random_int()`: Integer 0-10,000,000

### Test Scenarios

**`benchmark/scenarios/accepted_flow.py`** (16 lines)
- `build_event()`: Creates valid event
- Event should reach `thesis_ledger`

**`benchmark/scenarios/rejected_flow.py`** (26 lines)
- `build_expired_event()`: Creates event outside replay window
- Timestamp set to `current_time - replay_window_ms - 1000`
- Event should reach `thesis_audit` without touching DynamoDB

**`benchmark/scenarios/duplicate_scenario.py`** (16 lines)
- `build_duplicate_events()`: Two events with same eventId
- First invocation: accepted
- Second invocation: rejected by dedup

**`benchmark/scenarios/replay_scenario.py`** (9 lines)
- `build_replay_events()`: Alias to duplicate scenario
- Represents replay attack with same eventId/signature

### Result Collection

**`benchmark/collectors/result_collector.py`** (59 lines)
- `CompletionResult` dataclass: Event outcome info
  - Outcome (ACCEPTED/REJECTED)
  - Matched expected outcome
  - DynamoDB record
  - Timestamp when persisted
- `wait_for_outcome()`: Routes to ledger or audit collector

**`benchmark/collectors/ledger_collector.py`** (28 lines)
- `wait_for_event()`: Polls `thesis_ledger` with timeout
- `fetch_event()`: Direct DynamoDB query by eventId
- Configurable polling interval

**`benchmark/collectors/audit_collector.py`** (31 lines)
- `wait_for_event()`: Polls `thesis_audit` with timeout
- `fetch_event()`: Scans table with FilterExpression on eventId
- Same interface as LedgerCollector

### Metrics and Statistics

**`benchmark/metrics/latency_metrics.py`** (24 lines)
- `build_metrics()`: Aggregates all results
- Computes statistics for:
  - Producer latency (invoke time)
  - End-to-end latency (total time)
  - Outcome summary (success/rejection rates)

**`benchmark/metrics/statistics.py`** (47 lines)
- `summarize_latency()`: Calculates min, max, average, percentiles
- `summarize_outcomes()`: Calculates total, success rate, rejection rate
- Handles empty datasets gracefully

**`benchmark/metrics/percentile_metrics.py`** (11 lines)
- `percentile()`: Computes exact percentile from sorted values
- Proper boundary handling
- Returns None for empty datasets

### Output Exporters

**`benchmark/output/csv_writer.py`** (19 lines)
- `write_csv()`: Exports all result rows as CSV
- Creates parent directory if needed
- Uses DictWriter for automatic header
- One row per Lambda invocation

**`benchmark/output/json_writer.py`** (11 lines)
- `write_json()`: Exports comprehensive report
- Includes runtime config, metrics, all result rows
- Pretty-printed with indentation

### Configuration

**`benchmark/config/experiment_config.yaml`** (252 lines, NEW)
- YAML configuration defining 29 experiments
- Organized into 7 groups:
  - Cold-start baselines (3)
  - Warm runs (3)
  - Payload variation (3)
  - Replay protection (3)
  - Deduplication (3)
  - Expiration/replay window (3)
  - Smoke test (1)

## Data Structures

### ExperimentConfig
```python
@dataclass(frozen=True)
class ExperimentConfig:
    name: str
    scenario: str                    # accepted, expired, duplicate, replay
    algorithm: str                   # HMAC_SHA256, RSA_PSS_SHA256, ECDSA_P256_SHA256
    payload_size: str                # small, medium, large
    policy_mode: str                 # default or custom
    iterations: int                  # Number of invocations
    expected_outcome: str             # ACCEPTED or REJECTED
    key_id: str | None
    replay_window_ms: int
    wait_for_completion: bool
    completion_timeout_seconds: float
    poll_seconds: float
    cold_start_mode: str             # none, per_iteration, per_experiment, idle_wait
    idle_wait_seconds: float
    reset_between_iterations: bool
```

### ScenarioExecutionRequest
```python
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
```

### EventBuildOptions
```python
@dataclass(frozen=True)
class EventBuildOptions:
    algorithm: str
    key_id: str
    payload_size: str
    timestamp_epoch_ms: int | None = None
    event_id: str | None = None
```

### CompletionResult
```python
@dataclass(frozen=True)
class CompletionResult:
    outcome: str                      # ACCEPTED or REJECTED
    matched: bool                     # Matched expected outcome
    record: dict | None               # DynamoDB item
    completed_at_ms: int | None       # When event was persisted
```

## Dependencies

All dependencies in `benchmark/requirements.txt`:
- `boto3>=1.34.0` — AWS SDK (Lambda, DynamoDB)
- `botocore>=1.34.0` — AWS service models
- `cryptography>=42.0.0` — Cryptographic operations
- `PyYAML>=6.0` — YAML configuration parsing

## Execution Flow

```
1. benchmark_runner.py
   ↓
   Load experiment config (YAML)
   Create AWS clients (boto3)
   ↓
   For each experiment:
     ↓
     experiment_runner.py
     ├─ Reset environment (if needed)
     │
     ├─ For each iteration:
     │  ↓
     │  scenario_runner.py
     │  ├─ Build event (generators)
     │  ├─ Invoke Producer Lambda (boto3)
     │  ├─ Measure producer latency
     │  ├─ Optionally wait for completion (collectors)
     │  └─ Build result row
     │
     └─ Return all rows for experiment
   ↓
   Aggregate metrics (metrics)
   Export CSV/JSON (output)
```

## Result Output Schema (CSV)

One column per field in result row:
- `scenario`: Type of test
- `iteration`: Which iteration (1..N)
- `event_id`: Unique event identifier
- `algorithm`: Cryptographic algorithm used
- `key_id`: Key identifier from Secrets Manager
- `payload_size`: small/medium/large
- `policy_mode`: Policy configuration
- `expected_outcome`: ACCEPTED or REJECTED
- `final_outcome`: Actual outcome
- `matched_expected_outcome`: True if final matches expected
- `producer_latency_ms`: Invoke time in milliseconds
- `end_to_end_latency_ms`: Total time to ledger/audit
- `producer_cold_start`: Whether Lambda had cold start
- `producer_event_id`: Echo from producer response
- `invocation_count`: 1 (single) or 2 (pair)
- `invoke_started_at_ms`: Timestamp when invoked
- `invoke_ended_at_ms`: Timestamp when producer returned
- `experiment`: Experiment name

## Result Output Schema (JSON)

```json
{
  "runtime": {
    "localstack_endpoint": "...",
    "aws_region": "...",
    "producer_function_name": "...",
    "ledger_table": "...",
    "audit_table": "..."
  },
  "metrics": {
    "producer_latency_ms": {
      "count": ...,
      "min": ...,
      "max": ...,
      "average": ...,
      "p50": ...,
      "p95": ...,
      "p99": ...
    },
    "end_to_end_latency_ms": { ... },
    "outcomes": {
      "total": ...,
      "success_rate": ...,
      "rejection_rate": ...
    }
  },
  "results": [
    { ... row 1 ... },
    { ... row 2 ... },
    ...
  ]
}
```

## Integration Points

### Inputs
- LocalStack SQS queue: `thesis-events`
- LocalStack Lambda: `thesis-producer` (function name)
- LocalStack DynamoDB: `thesis_ledger`, `thesis_audit` (tables)

### Outputs
- CSV file: `benchmark/output/results/benchmark_results.csv`
- JSON file: `benchmark/output/results/benchmark_results.json`

### Dependencies
- Story 11: Validation Lambda with replay/dedup security
- Producer Lambda: Event signing and queue submission
- Consumer Lambda: Event processing from SQS
- Localstack: Full infrastructure simulation

## Extensibility Points

1. **New Scenarios**: Add file to `benchmark/scenarios/`, implement builder, register in `scenario_runner.py`
2. **New Metrics**: Add computation in `benchmark/metrics/statistics.py`
3. **New Output Formats**: Create new writer in `benchmark/output/`
4. **New Experiments**: Edit `benchmark/config/experiment_config.yaml`
5. **Custom Cold-Start Logic**: Extend `ExperimentRunner.run_experiment()`

## Testing and Validation

All modules compile without errors:
```bash
python3 -m py_compile benchmark/**/*.py
```

YAML configuration is valid:
```bash
python3 -c "import yaml; yaml.safe_load(open('benchmark/config/experiment_config.yaml'))"
```

Individual modules can be imported:
```bash
python3 -c "from benchmark.runner.benchmark_runner import *"
```

## Documentation Files

**`STORY_12_IMPLEMENTED.md`** (477 lines)
- Comprehensive implementation details
- Architecture context and design decisions
- Feature descriptions for all components
- Configuration file structure
- Usage examples
- Next steps and integration notes

**`STORY_12_QUICK_REFERENCE.md`** (quick lookup)
- Module responsibility matrix
- Experiment list
- Key features checklist
- Performance characteristics
- Quick start commands

This manifest and the implementation are complete and ready for testing with LocalStack.

