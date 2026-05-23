# Story 14 — Implement Experiment Configuration and Scenario System

## Goal

Implement a configurable experiment and scenario subsystem that allows the benchmark framework to execute reproducible benchmark runs using predefined configurations.

The subsystem should make it possible to define experiments without changing source code.

Experiments should support variations in:

- algorithms
- payload sizes
- replay behavior
- deduplication behavior
- cache modes
- rotation modes
- accepted/rejected flows
- cold/warm execution modes

The configuration system becomes the control plane for the benchmark platform.

---

## Why this story matters

Without a structured configuration system, every benchmark change would require modifying benchmark code directly.

That would create:

- inconsistent experiments
- difficult reproducibility
- configuration duplication
- manual benchmark management

The scenario system allows the thesis to define experiments declaratively.

This is important because a thesis benchmark must be:

- repeatable
- controlled
- comparable
- extensible

The scenario subsystem transforms the benchmark from a script into a real experimentation framework.

---

## Architecture context

Before this story:

```text
benchmark runner
   |
   └── hardcoded experiment logic
```

After this story:

```text
experiment configuration
   |
   v
scenario system
   |
   v
benchmark runner
   |
   v
platform execution
```

---

## High-level concept

Experiments should be described through configuration rather than source-code changes.

Conceptual flow:

```text
load scenario
   ↓
apply configuration
   ↓
generate workload
   ↓
execute benchmark
   ↓
collect results
```

This allows experiments to be versioned and reused.

---

## Module location

```text
benchmark/
```

Recommended structure:

```text
benchmark/
├── config/
│   ├── experiment_config.yaml
│   ├── accepted_flow.yaml
│   ├── replay_attack.yaml
│   ├── duplicate_attack.yaml
│   └── cold_start_comparison.yaml
├── scenarios/
│   ├── scenario_loader.py
│   ├── scenario_executor.py
│   ├── scenario_validator.py
│   └── scenario_result.py
└── models/
    ├── experiment_definition.py
    ├── workload_definition.py
    └── execution_mode.py
```

Keep the first implementation simple and explicit.

---

## Experiment definition

An experiment should describe:

- what to execute
- how many times to execute it
- which platform settings to use
- what metrics to collect

Suggested fields:

```text
experimentId
description
algorithm
payloadSize
iterations
concurrency
coldStartMode
replayEnabled
dedupEnabled
cacheEnabled
allowPreviousKey
expectedOutcome
```

Optional future fields:

```text
warmupIterations
batchSize
failureInjection
delayBetweenInvocations
```

---

## Scenario categories

The platform should support multiple scenario types.

### Accepted flow scenario

Valid event reaches ledger successfully.

Purpose:

- baseline performance measurement

---

### Invalid signature scenario

Event fails verification and reaches audit table.

Purpose:

- rejected-path performance analysis

---

### Replay scenario

Old timestamp event is rejected.

Purpose:

- replay protection overhead analysis

---

### Duplicate scenario

Repeated eventId is rejected.

Purpose:

- deduplication overhead analysis

---

### Rotation scenario

Validation succeeds using previous key.

Purpose:

- rotation overhead analysis

---

### Cold start comparison scenario

Compare:

```text
cold
vs
warm
```

invocations.

Purpose:

- startup sensitivity analysis

---

## Configuration format

The first implementation should use:

```text
YAML
```

Reason:

- human-readable
- easy to version
- suitable for benchmark configuration

Example conceptual structure:

```yaml
experimentId: rsa-cold-start
algorithm: RSA_PSS_SHA256
iterations: 100
payloadSize: medium
coldStartMode: true
replayEnabled: true
dedupEnabled: true
cacheEnabled: false
expectedOutcome: ACCEPTED
```

---

## Scenario loader

Responsibilities:

- load YAML configuration
- validate required fields
- transform configuration into runtime model

The loader should fail fast on invalid configuration.

---

## Scenario validator

Responsibilities:

- validate configuration correctness
- ensure compatible options
- prevent invalid combinations

Examples:

```text
rotation enabled without previous key
```

or:

```text
invalid algorithm value
```

---

## Scenario executor

Responsibilities:

- apply experiment configuration
- invoke benchmark runner
- orchestrate iterations
- collect results

The executor becomes the bridge between configuration and execution.

---

## Workload generation

The scenario system should support workload variation.

Examples:

### Small payload workload

Purpose:

- measure crypto-focused overhead

---

### Large payload workload

Purpose:

- measure serialization and signing scaling

---

### Mixed workload

Purpose:

- simulate more realistic traffic

---

## Execution modes

Suggested execution modes:

### Sequential

One invocation at a time.

Purpose:

- cleaner timing analysis

---

### Concurrent

Multiple invocations simultaneously.

Purpose:

- stress behavior analysis

The first implementation may focus on sequential execution.

---

## Cold start configuration

The scenario system should support:

```text
coldStartMode=true/false
```

Examples:

### Cold mode

Reset environment between iterations.

---

### Warm mode

Reuse environment across iterations.

This allows controlled startup comparisons.

---

## Cache configuration

The scenario system should support:

```text
cacheEnabled=true/false
```

Purpose:

- compare cached vs uncached key behavior

The benchmark should pass this configuration into the platform environment.

---

## Expected outcome support

Each scenario should define an expected outcome.

Examples:

```text
ACCEPTED
REJECTED
```

Possible rejection expectations:

```text
INVALID_SIGNATURE
REPLAY_DETECTED
EXPIRED
```

This allows automatic benchmark validation.

---

## Result classification

Scenario execution should classify results.

Examples:

```text
expected accepted
actual accepted
→ success
```

```text
expected rejected
actual accepted
→ scenario failure
```

This prevents silent benchmark inconsistencies.

---

## Logging expectations

Scenario execution logs should clearly show:

```text
experimentId
iteration
algorithm
payload size
outcome
latency
```

Example:

```text
experiment=rsa-cold-start iteration=15 latencyMs=123 outcome=ACCEPTED
```

---

## Benchmark reproducibility

The scenario system should improve reproducibility by:

- centralizing configuration
- versioning experiment definitions
- minimizing hardcoded benchmark logic

This is critical for academic evaluation.

---

## Benchmark implications

This subsystem enables systematic experiment comparison across:

### Algorithms

- HMAC
- RSA-PSS
- ECDSA

### Validation strictness

- replay enabled/disabled
- dedup enabled/disabled

### Cache modes

- cache enabled
- cache disabled

### Key rotation

- current only
- current + previous

### Invocation types

- cold
- warm

### Outcomes

- accepted
- rejected

This becomes the basis of the evaluation matrix in the thesis.

---

## Smoke test expectations

A smoke test should be able to:

1. Load YAML experiment
2. Execute benchmark scenario
3. Generate events
4. Produce benchmark results
5. Validate expected outcome
6. Export metrics

---

## Acceptance criteria

This story is complete when:

1. Scenario configuration system exists.
2. YAML experiment definitions are supported.
3. Scenario loader exists.
4. Scenario validator exists.
5. Scenario executor exists.
6. Benchmark execution can be configured without code changes.
7. Expected outcomes are validated.
8. Cold/warm modes are configurable.
9. Replay/dedup/cache options are configurable.
10. Benchmark logs include scenario metadata.

---

## Out of scope

Do not implement yet:

- distributed benchmark scheduling
- web UI for scenarios
- automatic chart generation
- statistical significance testing
- Kubernetes orchestration
- multi-cloud scenario execution
- AI-generated workloads

This story focuses only on configurable experiment orchestration and scenario management.
