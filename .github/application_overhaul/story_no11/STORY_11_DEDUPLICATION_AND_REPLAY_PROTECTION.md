# Story 11 — Implement Deduplication and Replay Protection

## Goal

Implement a deduplication and replay-protection subsystem that prevents duplicate or expired events from being processed multiple times.

This subsystem should protect the platform against:

- replayed messages
- duplicated SQS deliveries
- delayed events outside the allowed replay window
- repeated benchmark submissions using the same eventId

The subsystem becomes part of the Validation Lambda security enforcement flow.

---

## Why this story matters

Serverless messaging systems such as SQS operate with:

```text
at-least-once delivery
```

This means the same message may be delivered more than once.

Without deduplication, the system could:

- process the same event multiple times
- write duplicate ledger records
- produce inconsistent benchmark results

Replay protection is also important because cryptographically valid messages should not remain valid forever.

An attacker or faulty client could resend old messages unless the system enforces freshness constraints.

This story adds realistic security protections and operational correctness to the platform.

---

## Architecture context

Before this story:

```text
Validation Lambda
   |
   ├── signature verification
   ├── routing
   └── persistence/audit
```

After this story:

```text
Validation Lambda
   |
   ├── signature verification
   ├── replay protection
   ├── deduplication
   ├── routing
   └── persistence/audit
```

---

## High-level concepts

### Replay protection

Replay protection checks whether an event is too old.

Conceptually:

```text
currentTime - event.timestamp <= replayWindow
```

If the event exceeds the configured window:

```text
reject
```

---

### Deduplication

Deduplication checks whether the same eventId has already been processed.

If yes:

```text
reject duplicate
```

If no:

```text
mark as processed
continue validation
```

---

## Why replay and dedup are different

Replay protection focuses on:

```text
event freshness
```

Deduplication focuses on:

```text
event uniqueness
```

Examples:

### Fresh but duplicated

```text
same eventId resent immediately
```

Replay window passes, but dedup should reject.

---

### Old but unique

```text
never seen before
but timestamp is 2 hours old
```

Dedup passes, but replay protection should reject.

Both mechanisms are needed.

---

## Module location

The subsystem should primarily live inside:

```text
validation-lambda/
```

Recommended package structure:

```text
validation-lambda/
└── src/main/java/com/alexthesis/validation/
    ├── replay/
    │   ├── ReplayChecker.java
    │   ├── ReplayDecision.java
    │   └── ReplayConfiguration.java
    └── dedup/
        ├── DedupStore.java
        ├── DedupDecision.java
        ├── DedupRepository.java
        └── ProcessedEventRecord.java
```

Keep the first implementation simple.

---

## Replay protection behavior

Replay checking should be configurable.

Suggested configuration:

```text
thesis.security.replay-check-enabled=true
thesis.security.replay-window-ms=300000
```

Example:

```text
5 minute replay window
```

Validation logic:

```text
currentEpochMs - event.timestampEpochMs <= replayWindowMs
```

If false:

```text
reject as EXPIRED
```

---

## Replay decision flow

Conceptual flow:

```text
receive event
   ↓
extract timestamp
   ↓
compare with current time
   ↓
inside window?
   |
   yes → continue
   |
   no  → reject
```

---

## Deduplication store

Deduplication should use DynamoDB table:

```text
thesis_dedup
```

Purpose:

- store processed eventIds
- prevent duplicate processing
- support replay detection across invocations

Suggested primary key:

```text
eventId
```

---

## Dedup record model

Suggested fields:

```text
eventId
processedAtEpochMs
algorithm
keyId
```

Optional future fields:

```text
policyId
sourceLambda
processingStatus
```

Keep the first implementation minimal.

---

## Deduplication flow

Conceptual flow:

```text
receive event
   ↓
check eventId in DynamoDB
   ↓
exists?
   |
   yes → reject duplicate
   |
   no
   ↓
store eventId
   ↓
continue validation
```

---

## Validation ordering

Recommended validation order:

```text
1. Deserialize
2. Policy checks
3. Replay protection
4. Deduplication
5. Signature verification
6. Routing
```

Alternative orderings are possible, but replay and dedup should occur before expensive downstream operations where reasonable.

This ordering should later be discussed in the thesis evaluation.

---

## Dedup consistency considerations

SQS is asynchronous and distributed.

Duplicate events may arrive nearly simultaneously.

For the first implementation:

### Acceptable approach

Simple existence check + insert.

---

### Future stronger approach

Conditional DynamoDB writes.

Example:

```text
insert only if eventId does not exist
```

The stronger approach may be added later if needed.

---

## Error handling behavior

### Replay rejection

Behavior:

```text
route to rejected queue
do not throw
```

Reason:

Replay rejection is a business/security decision, not infrastructure failure.

---

### Duplicate rejection

Behavior:

```text
route to rejected queue
do not throw
```

---

### Infrastructure failure

Examples:

- DynamoDB unavailable
- query failure
- timeout
- serialization failure

Behavior:

```text
throw exception
allow SQS retry
```

---

## Rejection reasons

Replay and dedup should use shared audit reasons.

Replay expiration:

```text
EXPIRED
```

Duplicate detection:

```text
REPLAY_DETECTED
```

These should appear in:

```text
RejectedEvent
AuditRecord
```

---

## Policy integration

Replay and dedup behavior should be controlled through the policy engine.

Examples:

### Strict policy

```text
replay enabled = true
dedup enabled = true
```

---

### Relaxed policy

```text
replay enabled = false
dedup enabled = false
```

The Validation Lambda should not hardcode replay/dedup behavior directly.

---

## Benchmark implications

This story introduces important benchmark dimensions.

The benchmark should later compare:

### Replay enabled vs disabled

Measure:

- timestamp validation overhead

---

### Dedup enabled vs disabled

Measure:

- DynamoDB read/write overhead

---

### Cache warm vs cold dedup access

Measure:

- database access effects on latency

---

### Duplicate flood scenarios

Measure:

- rejection throughput
- retry behavior
- audit path load

---

## Observability value

Replay and dedup metrics are useful for:

- detecting benchmark mistakes
- validating event uniqueness
- measuring invalid traffic
- identifying duplicate deliveries

---

## Smoke test expectations

A smoke test should be able to:

### Replay test

1. Send old event
2. Observe rejection
3. Confirm audit reason = EXPIRED

---

### Duplicate test

1. Send same eventId twice
2. First accepted
3. Second rejected
4. Confirm audit reason = REPLAY_DETECTED

---

## Configuration

Suggested properties:

```text
thesis.security.replay-check-enabled=true
thesis.security.replay-window-ms=300000

thesis.security.dedup-enabled=true

thesis.dynamodb.dedup-table=thesis_dedup
```

---

## Acceptance criteria

This story is complete when:

1. Replay checking exists.
2. Replay window is configurable.
3. Old events are rejected.
4. Deduplication store exists.
5. Duplicate events are rejected.
6. Dedup records are persisted in DynamoDB.
7. Replay and dedup integrate with policy engine.
8. Replay and dedup integrate with rejected routing.
9. Infrastructure failures throw exceptions.
10. Smoke tests confirm replay and duplicate rejection behavior.

---

## Out of scope

Do not implement yet:

- distributed locking
- DynamoDB transactions
- Bloom filters
- Redis-based deduplication
- advanced replay analytics
- adaptive replay windows
- cross-region deduplication

This story focuses only on replay protection and duplicate event prevention.
