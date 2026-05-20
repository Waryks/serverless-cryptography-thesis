# Story 9 — Implement Persistence Lambda

## Goal

Implement the Persistence Lambda responsible for consuming accepted events and writing final trusted records into the ledger table.

This Lambda represents the successful business-processing stage of the platform.

It should persist validated events that successfully passed:

- signature verification
- policy validation
- replay checks
- deduplication checks

The Persistence Lambda becomes the final successful destination for trusted events.

---

## Why this story matters

Before this story, accepted events only exist inside queues.

There is no durable business state.

This story introduces:

- final persistence
- trusted event storage
- successful transaction history
- benchmark completion visibility

The ledger table becomes the authoritative source of accepted events.

This is important for both:

- architectural realism
- benchmark measurement

Without persistence, the system behaves mostly like a transient queue pipeline.

With persistence, it becomes a real transaction-style event platform.

---

## Architecture context

Before this story:

```text
Producer Lambda
   |
   v
Ingress Queue
   |
   v
Validation Lambda
   |
   v
Accepted Queue
```

After this story:

```text
Producer Lambda
   |
   v
Ingress Queue
   |
   v
Validation Lambda
   |
   v
Accepted Queue
   |
   v
Persistence Lambda
   |
   v
DynamoDB: thesis_ledger
```

---

## Ledger concept

The ledger represents the final accepted state of the system.

Only trusted and validated events should be written into:

```text
thesis_ledger
```

This table should represent:

```text
validated transaction history
```

Even though the thesis is not implementing a real banking system, the architecture should simulate a transaction-like processing platform.

---

## Module location

```text
persistence-lambda/
```

Recommended package structure:

```text
persistence-lambda/
└── src/main/java/com/alexthesis/persistence/
    ├── handler/
    │   └── PersistenceHandler.java
    ├── service/
    │   └── PersistenceService.java
    ├── repository/
    │   └── LedgerRepository.java
    ├── model/
    │   └── LedgerRecord.java
    └── mapping/
        └── LedgerMapper.java
```

Keep the first implementation simple and explicit.

---

## Input source

The Persistence Lambda should be triggered by:

```text
thesis-accepted-events
```

through an SQS event source mapping.

The Lambda should receive:

```text
SQSEvent
```

Each record body contains a serialized:

```text
SignedEvent
```

The Persistence Lambda should not manually poll SQS.

---

## Responsibilities

The Persistence Lambda must:

1. Receive accepted events from SQS
2. Deserialize `SignedEvent`
3. Validate minimal required fields
4. Transform event into ledger model
5. Persist ledger record into DynamoDB
6. Log successful persistence
7. Throw on infrastructure failures so SQS retry occurs

This Lambda should not:

- verify signatures
- apply policy checks
- perform replay checks
- perform deduplication

Those belong to the Validation Lambda.

The Persistence Lambda assumes incoming events are already trusted.

---

## Ledger record model

The ledger should store normalized persistence records.

Suggested fields:

```text
eventId
algorithm
keyId
payload
signatureB64
acceptedAtEpochMs
persistedAtEpochMs
```

Optional future fields:

```text
policyId
validationLatencyMs
producerLatencyMs
coldStartFlags
```

The first implementation should remain minimal.

---

## DynamoDB table

Table:

```text
thesis_ledger
```

Suggested primary key:

```text
eventId (string)
```

The table should contain only accepted events.

Rejected events belong in:

```text
thesis_audit
```

---

## Persistence flow

Conceptual flow:

```text
receive SignedEvent
   ↓
deserialize
   ↓
map to LedgerRecord
   ↓
write to DynamoDB
   ↓
success
```

---

## LedgerMapper

The mapper should convert:

```text
SignedEvent
```

into:

```text
LedgerRecord
```

Purpose:

- separate persistence model from transport model
- keep repository layer clean
- allow future schema evolution

---

## LedgerRepository

Responsibilities:

- interact with DynamoDB
- write ledger records
- retrieve records if needed later
- encapsulate database logic

The repository should not contain business validation logic.

---

## Error handling behavior

### Successful persistence

Behavior:

```text
return successfully
SQS message deleted
```

---

### Infrastructure failure

Examples:

- DynamoDB unavailable
- write failure
- serialization failure
- permissions issue

Behavior:

```text
throw exception
allow SQS retry
```

This ensures accepted events are not silently lost.

---

## Idempotency considerations

SQS uses at-least-once delivery.

The Persistence Lambda may receive duplicate messages.

The ledger persistence strategy should therefore be idempotent.

Possible approaches:

### Option A — overwrite same eventId

Simple and acceptable initially.

---

### Option B — conditional write

Only insert if eventId does not exist.

Can be added later.

For the first implementation, Option A is acceptable.

---

## Logging expectations

Persistence logs should clearly show:

```text
eventId persisted successfully
```

Examples:

```text
eventId=123 persisted=true
```

These logs help benchmark debugging and pipeline tracing.

---

## Benchmark implications

The ledger table becomes the final success signal for the benchmark.

The benchmark should later be able to:

1. invoke Producer Lambda
2. wait until event appears in `thesis_ledger`
3. calculate end-to-end latency

This makes persistence a critical part of measurement.

---

## Smoke test expectations

A smoke test should be able to:

1. Send valid event into ingress queue
2. Observe validation acceptance
3. Observe event in accepted queue
4. Observe Persistence Lambda invocation
5. Confirm ledger record exists in `thesis_ledger`

At this stage, placeholder validation behavior is acceptable.

---

## Event source mapping

The following mapping should exist:

```text
thesis-accepted-events
   ↓
thesis-persistence
```

Batch size should initially remain:

```text
1
```

to preserve clean one-event-per-transaction measurements.

---

## Configuration

Suggested properties:

```text
quarkus.aws.region=eu-central-1

quarkus.sqs.endpoint-override=http://localhost:4566
quarkus.dynamodb.endpoint-override=http://localhost:4566

thesis.dynamodb.ledger-table=thesis_ledger
```

---

## Acceptance criteria

This story is complete when:

1. Persistence Lambda exists.
2. Lambda receives SQS `Records[]`.
3. Accepted events are deserialized successfully.
4. LedgerRecord mapping exists.
5. Records are persisted into `thesis_ledger`.
6. Persistence logs exist.
7. Infrastructure failures throw exceptions.
8. Event source mapping from accepted queue exists.
9. Smoke tests confirm end-to-end persistence flow.

---

## Out of scope

Do not implement yet:

- Audit Lambda
- advanced conditional writes
- optimistic locking
- transactional DynamoDB operations
- global secondary indexes
- analytics pipelines
- data retention policies
- performance dashboards

This story focuses only on durable persistence of accepted events.
