# Story 12 — Implement Benchmark Runner and Experiment Orchestration

## Goal

Implement a benchmark runner responsible for orchestrating experiments, generating events, invoking the Producer Lambda, collecting timing information, and producing reproducible benchmark results.

The benchmark runner becomes the central experimentation framework for the thesis.

It should support:

- automated experiment execution
- configurable workloads
- algorithm comparisons
- replay/dedup scenarios
- cache/no-cache scenarios
- accepted/rejected flow analysis
- cold-start-sensitive measurements

The benchmark subsystem should allow experiments to be repeatable, configurable, and extensible.

---

## Why this story matters

Without a benchmark orchestration layer, experiments would need to be executed manually.

Manual execution introduces:

- inconsistent measurements
- human error
- non-repeatable results
- uncontrolled environment resets

The benchmark runner transforms the project from:

```text
a secure serverless application
```

into:

```text
a measurable research platform
```

This story is critical because the benchmark framework is what ultimately generates the thesis evaluation data.

---

## Architecture context

Before this story:

```text
Producer Lambda
   ↓
Validation Lambda
   ↓
Persistence/Audit
```

After this story:

```text
Benchmark Runner
   ↓
Producer Lambda
   ↓
Validation Lambda
   ↓
Persistence/Audit
   ↓
Benchmark Result Collection
```

---

## High-level responsibilities

The benchmark runner must:

1. Generate benchmark events
2. Invoke the Producer Lambda
3. Wait for final system outcome
4. Measure timings
5. Classify results
6. Store benchmark results
7. Reset environment between runs if required
8. Support multiple experiment configurations

The benchmark should orchestrate the entire platform lifecycle during experiments.

---

## Module location

```text
benchmark/
```

Recommended structure:

```text
benchmark/
├── runner/
│   ├── benchmark_runner.py
│   ├── experiment_runner.py
│   └── scenario_runner.py
├── scenarios/
│   ├── accepted_flow.py
│   ├── rejected_flow.py
│   ├── replay_scenario.py
│   └── duplicate_scenario.py
├── generators/
│   ├── payload_generator.py
│   ├── event_generator.py
│   └── random_data.py
├── collectors/
│   ├── result_collector.py
│   ├── ledger_collector.py
│   └── audit_collector.py
├── metrics/
│   ├── latency_metrics.py
│   ├── percentile_metrics.py
│   └── statistics.py
├── output/
│   ├── csv_writer.py
│   └── json_writer.py
└── config/
    └── experiment_config.yaml
```

The benchmark should remain modular and easy to extend.

---

## Benchmark flow

Conceptual flow:

```text
load experiment configuration
   ↓
reset local environment
   ↓
generate event
   ↓
invoke Producer Lambda
   ↓
wait for ledger/audit result
   ↓
calculate timings
   ↓
store benchmark result
   ↓
repeat
```

---

## Event generation

The benchmark runner should generate realistic random events.

Generated values may include:

- random UUID eventId
- timestamp
- random payload values
- variable payload sizes
- selected algorithm
- selected keyId

The benchmark becomes responsible for event generation rather than the Producer Lambda.

---

## Payload generation

Payloads should support variable sizes.

Example sizes:

```text
small
medium
large
```

Possible generation strategies:

- random UUID fields
- random strings
- nested JSON objects
- random numeric values

The payload does not need business realism. It exists to measure serialization and crypto overhead.

---

## Lambda invocation

The benchmark runner should invoke:

```text
thesis-producer
```

using:

- AWS SDK
- boto3
- or AWS CLI

The benchmark should measure:

```text
invoke start
→ producer response
```

This represents producer-side latency.

---

## End-to-end completion tracking

The benchmark runner should optionally wait for final system completion.

Accepted flow completion:

```text
event appears in thesis_ledger
```

Rejected flow completion:

```text
event appears in thesis_audit
```

This allows true end-to-end latency measurement.

---

## Timing collection

The benchmark should collect at least:

```text
producer invocation latency
end-to-end latency
success/failure outcome
cold start flag
algorithm
payload size
policy mode
```

Optional future metrics:

```text
verification latency
replay check latency
dedup latency
queue delay
DynamoDB latency
```

---

## Cold start experiments

The benchmark runner should support controlled cold-start scenarios.

Possible strategies:

### Strategy A — environment restart

Restart LocalStack or redeploy Lambda.

---

### Strategy B — idle timeout simulation

Wait long enough between invocations.

---

### Strategy C — Lambda recreation

Delete and recreate Lambda containers.

For the first implementation, Strategy A or B is acceptable.

---

## Warm invocation experiments

The benchmark should also support warm runs.

Example:

```text
100 sequential invocations
without environment reset
```

This allows comparison between:

```text
cold
vs
warm
```

behavior.

---

## Experiment configuration

Experiments should be configurable.

Suggested fields:

```text
algorithm
payload_size
replay_enabled
dedup_enabled
allow_previous_key
cache_enabled
iterations
concurrency
cold_start_mode
```

Configuration may initially use:

```text
YAML
JSON
CLI arguments
```

---

## Scenario support

The benchmark should support multiple scenarios.

### Accepted flow

Valid event successfully reaches ledger.

---

### Invalid signature

Event reaches audit table.

---

### Expired event

Replay protection rejects event.

---

### Duplicate event

Deduplication rejects repeated eventId.

---

### Previous key verification

Validation succeeds using previous rotated key.

---

## Result collection

The benchmark should collect results from:

```text
thesis_ledger
```

and:

```text
thesis_audit
```

This confirms final platform state.

---

## Output formats

Benchmark results should be exportable.

Suggested formats:

```text
CSV
JSON
```

CSV is especially useful for:

- thesis charts
- statistical analysis
- spreadsheet import

---

## Metrics and statistics

The benchmark should compute:

```text
average latency
min latency
max latency
p50
p95
p99
success rate
rejection rate
```

These metrics are important for the evaluation chapter.

---

## Environment reset support

The benchmark runner should integrate with:

```text
localstack/reset.py
```

Purpose:

- clear queues
- clear DynamoDB tables
- reset benchmark state
- prepare reproducible runs

This is especially important for replay/dedup experiments.

---

## Logging expectations

Benchmark logs should clearly show:

```text
scenario
iteration
eventId
latency
outcome
```

Examples:

```text
iteration=5 algorithm=RSA_PSS_SHA256 latencyMs=123 outcome=ACCEPTED
```

---

## Benchmark dimensions

The benchmark should later support experiments across:

### Algorithms

- HMAC
- RSA-PSS
- ECDSA

---

### Payload sizes

- small
- medium
- large

---

### Replay modes

- enabled
- disabled

---

### Dedup modes

- enabled
- disabled

---

### Key cache modes

- enabled
- disabled

---

### Rotation modes

- current key only
- current + previous key

---

### Invocation types

- cold
- warm

These dimensions form the basis of the thesis evaluation.

---

## Smoke test expectations

A smoke test should be able to:

1. Generate benchmark event
2. Invoke Producer Lambda
3. Observe final ledger/audit result
4. Print latency result
5. Export benchmark output

At this stage, simple CSV output is sufficient.

---

## Acceptance criteria

This story is complete when:

1. Benchmark runner exists.
2. Benchmark can invoke Producer Lambda.
3. Benchmark generates events dynamically.
4. Benchmark supports configurable experiments.
5. Benchmark can wait for ledger completion.
6. Benchmark can wait for audit completion.
7. Benchmark collects latency metrics.
8. Benchmark exports CSV or JSON results.
9. Benchmark supports accepted and rejected scenarios.
10. Benchmark supports cold and warm experiments.

---

## Out of scope

Do not implement yet:

- Grafana dashboards
- distributed benchmark clusters
- Kubernetes orchestration
- machine learning analysis
- advanced statistical modeling
- cross-cloud orchestration
- automated thesis chart generation

This story focuses only on experiment orchestration and benchmark execution.