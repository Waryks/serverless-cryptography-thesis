# Story 13 — Implement Performance Instrumentation and Timing Collection

## Goal

Implement a platform-wide instrumentation subsystem capable of measuring and collecting timing information across all major processing stages.

The instrumentation layer should allow the thesis to precisely measure:

- partial cold-start effects
- cryptographic overhead
- queue-to-queue latency
- policy evaluation overhead
- replay/dedup overhead
- persistence latency
- audit latency
- end-to-end processing latency

The instrumentation subsystem becomes the foundation for the thesis evaluation chapter.

---

## Why this story matters

The benchmark runner alone is not sufficient for detailed performance analysis.

External timing only provides:

invoke start → invoke end

However, the thesis requires deeper visibility into where latency is introduced.

Without instrumentation, the platform cannot answer questions such as:

- How much time is spent loading keys?
- How much time does signature verification add?
- What is the replay check overhead?
- How much latency comes from DynamoDB?
- How much latency comes from queue routing?
- How much does policy evaluation cost?

This story introduces observability into the system itself.

---

## Architecture context

Before this story:

Benchmark Runner
   |
   └── external latency only

After this story:

Benchmark Runner
   |
   └── detailed internal timing metrics
            |
            ├── producer timings
            ├── validation timings
            ├── replay timings
            ├── dedup timings
            ├── persistence timings
            └── audit timings

---

## Instrumentation scope

Instrumentation should cover:

### Producer Lambda

- invocation duration
- key retrieval
- key parsing
- serialization
- signing
- SQS publishing

### Validation Lambda

- deserialization
- policy loading
- replay check
- dedup lookup
- signature verification
- routing
- accepted/rejected publishing

### Persistence Lambda

- deserialization
- DynamoDB persistence
- ledger mapping

### Audit Lambda

- deserialization
- audit mapping
- DynamoDB persistence

---

## Module location

Instrumentation utilities should primarily live in:

common/

Recommended package structure:

- TimingCollector.java
- TimingSnapshot.java
- TimingStage.java
- MetricsContext.java
- MetricsRecorder.java
- ColdStartTracker.java

---

## TimingStage examples

### Producer stages

- PRODUCER_TOTAL
- KEY_LOADING
- KEY_PARSING
- CONTENT_SERIALIZATION
- SIGNING
- SQS_PUBLISH

### Validation stages

- VALIDATION_TOTAL
- POLICY_LOADING
- REPLAY_CHECK
- DEDUP_CHECK
- SIGNATURE_VERIFICATION
- ROUTING
- ACCEPTED_PUBLISH
- REJECTED_PUBLISH

### Persistence stages

- PERSISTENCE_TOTAL
- LEDGER_MAPPING
- LEDGER_WRITE

### Audit stages

- AUDIT_TOTAL
- AUDIT_MAPPING
- AUDIT_WRITE

---

## Cold start tracking

Each Lambda should expose:

coldStart=true/false

using:

static boolean firstInvocation

This allows benchmark correlation between cold and warm runs.

---

## Measurement strategy

Use:

System.nanoTime()

for duration measurement.

Convert to milliseconds only for display/export.

---

## Logging expectations

Example logs:

eventId=123 stage=SIGNING durationMs=5.23

eventId=456 stage=DEDUP_CHECK durationMs=2.14

---

## Benchmark implications

Instrumentation enables:

- crypto overhead analysis
- replay overhead analysis
- dedup overhead analysis
- DynamoDB latency analysis
- routing latency analysis
- end-to-end breakdowns

---

## Acceptance criteria

- Timing subsystem exists
- Named timing stages exist
- All Lambdas collect timings
- Cold start tracking exists
- Benchmark can consume timing data
- Nanosecond precision is used internally

---

## Out of scope

- OpenTelemetry
- Grafana
- Prometheus
- distributed tracing
- X-Ray
