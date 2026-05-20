# Story 10 — Implement Audit Lambda

## Goal

Implement the Audit Lambda responsible for consuming rejected events and persisting audit/security records into the audit table.

This Lambda represents the security and observability path of the platform.

It should preserve validation failures instead of silently discarding them.

The Audit Lambda becomes responsible for durable recording of:

- invalid signatures
- expired events
- replay attempts
- unknown keys
- policy rejections
- deserialization failures

This creates a realistic secure event-processing architecture with operational visibility.

---

## Why this story matters

Without an audit subsystem, rejected events disappear after validation.

That creates several problems:

- no observability
- no traceability
- no rejection history
- no debugging visibility
- no security evidence

Real secure event-processing systems almost always preserve rejected security events.

This story adds operational realism and significantly strengthens the architectural depth of the thesis.

It also creates a dedicated rejected-event processing path, allowing the benchmark to compare:

```text
accepted flow
vs
rejected flow
```

---

## Architecture context

Before this story:

```text
Producer Lambda
   |
   v
Validation Lambda
   |
   +---- accepted ----> Accepted Queue
   |
   +---- rejected ----> Rejected Queue
```

After this story:

```text
Producer Lambda
   |
   v
Validation Lambda
   |
   +---- accepted ----> Accepted Queue
   |
   +---- rejected ----> Rejected Queue
                                 |
                                 v
                         Audit Lambda
                                 |
                                 v
                   DynamoDB: thesis_audit
```

---

## Audit concept

The audit subsystem represents the platform's security evidence layer.

It should preserve:

- why an event failed
- when it failed
- which policy rejected it
- which algorithm was involved
- which keyId was used
- what validation stage failed

This allows:

- debugging
- observability
- replay analysis
- benchmark rejection analysis
- future compliance/security reporting

---

## Module location

```text
audit-lambda/
```

Recommended package structure:

```text
audit-lambda/
└── src/main/java/com/alexthesis/audit/
    ├── handler/
    │   └── AuditHandler.java
    ├── service/
    │   └── AuditService.java
    ├── repository/
    │   └── AuditRepository.java
    ├── model/
    │   └── AuditRecord.java
    └── mapping/
        └── AuditMapper.java
```

Keep the first implementation simple.

---

## Input source

The Audit Lambda should be triggered by:

```text
thesis-rejected-events
```

through an SQS event source mapping.

The Lambda receives:

```text
SQSEvent
```

Each record body contains a serialized:

```text
RejectedEvent
```

The Audit Lambda should not manually poll SQS.

---

## Responsibilities

The Audit Lambda must:

1. Receive rejected events from SQS
2. Deserialize `RejectedEvent`
3. Transform rejected event into audit model
4. Persist audit record into DynamoDB
5. Log rejection details
6. Throw on infrastructure failures so retries occur

The Audit Lambda should not:

- perform signature verification
- perform replay checks
- apply policies
- reroute events

Those decisions were already made by the Validation Lambda.

---

## Audit record model

Suggested fields:

```text
auditId
eventId
reason
message
algorithm
keyId
payload
signatureB64
rejectedAtEpochMs
persistedAtEpochMs
```

Optional future fields:

```text
policyId
validationStage
validationLatencyMs
coldStartFlags
stackTrace
```

Keep the first implementation minimal.

---

## Audit table

Table:

```text
thesis_audit
```

Suggested primary key:

```text
auditId (string)
```

Alternative:

```text
eventId
```

However, using `auditId` is recommended because:

- one event may generate multiple audit records later
- supports future audit evolution
- avoids overwrite scenarios

---

## AuditMapper

The mapper converts:

```text
RejectedEvent
```

into:

```text
AuditRecord
```

Purpose:

- separate transport model from persistence model
- support future schema changes
- keep repository clean

---

## AuditRepository

Responsibilities:

- persist audit records
- interact with DynamoDB
- encapsulate database logic

The repository should not contain business/security validation logic.

---

## Rejection reasons

The audit system should persist reasons from:

```text
AuditReason
```

Expected reasons include:

- INVALID_SIGNATURE
- EXPIRED
- REPLAY_DETECTED
- UNKNOWN_KEY
- ALGORITHM_MISMATCH
- POLICY_REJECTED
- DESERIALIZATION_ERROR
- INTERNAL_ERROR

These reasons are critical for benchmark analysis and debugging.

---

## Error handling behavior

### Successful audit persistence

Behavior:

```text
return successfully
SQS message deleted
```

---

### Infrastructure failure

Examples:

- DynamoDB unavailable
- serialization failure
- table write failure
- unexpected runtime exception

Behavior:

```text
throw exception
allow SQS retry
```

Rejected security events should not be silently lost because the audit path failed.

---

## Logging expectations

Audit logs should clearly show:

```text
eventId rejected reason=INVALID_SIGNATURE
```

Examples:

```text
eventId=123 auditPersisted=true reason=EXPIRED
```

These logs are useful for benchmark tracing and debugging.

---

## Benchmark implications

The audit table becomes the final observable destination for rejected flows.

The benchmark should later support:

### Accepted flow

```text
Producer
→ Validation
→ Accepted Queue
→ Persistence
→ Ledger
```

### Rejected flow

```text
Producer
→ Validation
→ Rejected Queue
→ Audit
→ Audit Table
```

This allows direct comparison between successful and failed security paths.

---

## Observability value

The audit subsystem provides:

- security traceability
- replay analysis
- operational debugging
- rejection statistics
- benchmark outcome classification

This is important because secure systems must not silently discard failures.

---

## Smoke test expectations

A smoke test should be able to:

1. Send invalid event into ingress queue
2. Observe Validation Lambda rejection
3. Observe rejected event in rejected queue
4. Observe Audit Lambda invocation
5. Confirm audit record exists in `thesis_audit`

Example scenarios:

```text
invalid signature
expired timestamp
unknown key
```

---

## Event source mapping

The following mapping should exist:

```text
thesis-rejected-events
   ↓
thesis-audit
```

Batch size should initially remain:

```text
1
```

to preserve clean one-event-per-measurement behavior.

---

## Configuration

Suggested properties:

```text
quarkus.aws.region=eu-central-1

quarkus.sqs.endpoint-override=http://localhost:4566
quarkus.dynamodb.endpoint-override=http://localhost:4566

thesis.dynamodb.audit-table=thesis_audit
```

---

## Accepted vs rejected separation

This story finalizes the architectural split between:

### Business persistence path

```text
accepted events
```

and

### Security/audit path

```text
rejected events
```

This separation is one of the key reasons the application now resembles a realistic secure event-processing platform.

---

## Acceptance criteria

This story is complete when:

1. Audit Lambda exists.
2. Lambda receives SQS `Records[]`.
3. Rejected events are deserialized successfully.
4. AuditRecord mapping exists.
5. Audit records are persisted into `thesis_audit`.
6. Audit logs exist.
7. Infrastructure failures throw exceptions.
8. Event source mapping from rejected queue exists.
9. Smoke tests confirm rejected event persistence flow.

---

## Out of scope

Do not implement yet:

- SIEM integration
- CloudWatch dashboards
- alerting
- retention policies
- audit analytics
- DLQs
- distributed tracing systems
- security reporting UI

This story focuses only on durable persistence of rejected/audit events.
