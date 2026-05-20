# Story 5 — Implement Validation Lambda

## Goal

Implement the Validation Lambda responsible for consuming signed events from the ingress queue, applying security checks, and routing events to either the accepted queue or the rejected queue.

This Lambda is the core security enforcement component of the platform.

---

## Why this story matters

The Validation Lambda transforms the application from a simple producer/consumer queue demo into a secure event-processing platform.

It is responsible for deciding whether an event should be trusted.

This is where the thesis system starts enforcing:

- signature verification
- algorithm compatibility
- key trust
- replay protection
- deduplication
- accepted/rejected routing

For this story, some checks may still be placeholders, but the structure must be correct and ready for the later policy and crypto stories.

---

## Architecture context

Before this story:

```text
Producer Lambda
   |
   v
SQS: thesis-ingress-events
   |
   v
Validation Lambda
```

After this story:

```text
Producer Lambda
   |
   v
SQS: thesis-ingress-events
   |
   v
Validation Lambda
   |                         |
   | accepted                | rejected
   v                         v
SQS: thesis-accepted-events  SQS: thesis-rejected-events
```

---

## Module location

```text
validation-lambda/
```

This module should be a Quarkus Lambda project.

Dependencies:

- common
- quarkus-amazon-lambda
- quarkus-amazon-sqs
- quarkus-amazon-secretsmanager
- quarkus-amazon-dynamodb
- quarkus-jackson
- aws-lambda-java-events

---

## Required input

The Validation Lambda is triggered by SQS.

It receives:

```text
SQSEvent
```

The event contains:

```text
Records[]
```

Each record body contains a serialized `SignedEvent`.

---

## Main responsibilities

The Validation Lambda must:

1. Parse each SQS record body into a `SignedEvent`
2. Validate basic event structure
3. Verify the signature
4. Check replay window if enabled
5. Check deduplication if enabled
6. Route valid events to `thesis-accepted-events`
7. Route invalid/rejected events to `thesis-rejected-events`
8. Avoid retrying events rejected for security reasons
9. Throw only for infrastructure/internal failures that should be retried

---

## Internal structure

Recommended structure:

```text
validation-lambda/
└── src/main/java/com/alexthesis/validation/
    ├── handler/
    │   └── ValidationHandler.java
    ├── service/
    │   └── ValidationService.java
    ├── crypto/
    │   └── SignatureVerifier.java
    ├── replay/
    │   └── ReplayChecker.java
    ├── dedup/
    │   └── DedupStore.java
    ├── routing/
    │   └── ValidationRouter.java
    └── reasons/
        └── RejectionDecision.java
```

Do not overengineer the first implementation. Components may start simple and evolve later.

---

## ValidationHandler

The handler is the Lambda entry point.

Responsibilities:

- receive `SQSEvent`
- iterate over `Records`
- pass each message body to `ValidationService`
- not manually poll SQS
- not contain business/security logic

The handler should return `Void`.

Important behavior:

- if validation rejects an event for security reasons, handler should not throw
- if infrastructure failure occurs, handler may throw to allow SQS retry

---

## ValidationService

The service orchestrates validation.

Responsibilities:

1. Deserialize body into `SignedEvent`
2. Validate required fields
3. Call signature verifier
4. Call replay checker
5. Call dedup checker
6. Route event based on decision

The service should make the final decision:

```text
accepted → accepted queue
rejected → rejected queue
```

---

## Signature verification

For this story, signature verification may initially be a placeholder.

Expected future behavior:

- deterministically serialize `SignedContent`
- load key material using keyId / policy
- verify based on algorithm
- support HMAC, RSA-PSS, and ECDSA
- optionally support current + previous key verification

Placeholder behavior is acceptable if clearly marked with TODO.

---

## Replay checking

Replay checking should be configurable.

Suggested properties:

```text
thesis.security.replay-check-enabled=true
thesis.security.replay-window-ms=300000
```

If enabled:

```text
currentTimeMillis - event.timestampEpochMs <= replayWindowMs
```

If the event is too old, route it to rejected queue.

---

## Deduplication

Deduplication should use DynamoDB table:

```text
thesis_dedup
```

For the first version, this can be a TODO or placeholder.

Final expected behavior:

- check whether eventId already exists
- if it exists, reject as replay/duplicate
- if it does not exist, mark it as seen

This protects against SQS at-least-once delivery and repeated event submissions.

---

## Routing

Validation Lambda should publish to two queues:

```text
thesis-accepted-events
thesis-rejected-events
```

### Accepted route

If all checks pass:

- publish original `SignedEvent` to accepted queue

### Rejected route

If validation fails:

- publish a `RejectedEvent` to rejected queue

A `RejectedEvent` should include:

- original event if available
- rejection reason
- message
- rejected timestamp

---

## Rejection reasons

Use the shared `AuditReason` enum from common.

Relevant reasons:

- INVALID_SIGNATURE
- EXPIRED
- REPLAY_DETECTED
- UNKNOWN_KEY
- ALGORITHM_MISMATCH
- POLICY_REJECTED
- DESERIALIZATION_ERROR
- INTERNAL_ERROR

---

## Error handling rules

This story must distinguish between security rejection and infrastructure failure.

### Security rejection

Examples:

- invalid signature
- expired event
- replay detected
- algorithm mismatch

Behavior:

- route to rejected queue
- do not throw
- allow SQS source message to be deleted

### Infrastructure failure

Examples:

- DynamoDB unavailable
- SQS publish failure
- Secrets Manager unavailable
- unexpected runtime exception

Behavior:

- throw exception
- allow SQS retry

This distinction is important for realistic SQS/Lambda behavior.

---

## Configuration

Required properties:

```text
quarkus.aws.region=eu-central-1
quarkus.sqs.endpoint-override=http://localhost:4566
quarkus.dynamodb.endpoint-override=http://localhost:4566
quarkus.secretsmanager.endpoint-override=http://localhost:4566

thesis.sqs.accepted-queue-name=thesis-accepted-events
thesis.sqs.rejected-queue-name=thesis-rejected-events

thesis.security.replay-check-enabled=true
thesis.security.replay-window-ms=300000
thesis.security.dedup-enabled=true
```

---

## Queue publisher behavior

The Validation Lambda needs to publish to accepted and rejected queues.

It should:

- resolve queue URLs from queue names
- cache queue URLs after resolution
- use synchronous SQS client
- serialize events with Jackson

---

## DynamoDB table usage

The Validation Lambda may interact with:

```text
thesis_dedup
```

It should not write accepted records to the ledger table. Ledger persistence belongs to the Persistence Lambda.

It should not write audit records directly. Audit persistence belongs to the Audit Lambda.

The Validation Lambda only routes decisions.

---

## Smoke test expectation

A smoke test should be able to:

1. Send a valid-looking `SignedEvent` to `thesis-ingress-events`
2. Confirm the Validation Lambda receives it
3. Confirm it routes the event to either:
   - `thesis-accepted-events`, or
   - `thesis-rejected-events`

For early implementation, placeholder signature validation may route all events as accepted.

---

## Acceptance criteria

This story is complete when:

1. Validation Lambda receives SQS `Records[]`.
2. Each record body is parsed as `SignedEvent`.
3. Basic validation flow exists.
4. Placeholder or real signature verification exists.
5. Replay check is configurable.
6. Dedup check has placeholder or initial implementation.
7. Accepted events are published to `thesis-accepted-events`.
8. Rejected events are published to `thesis-rejected-events`.
9. Security rejections do not throw.
10. Infrastructure failures throw.
11. The Lambda can be wired to `thesis-ingress-events` using event source mapping.

---

## Out of scope

Do not implement yet unless already available:

- full policy engine
- complete cryptographic verification for all algorithms
- final benchmark runner
- Persistence Lambda
- Audit Lambda
- final performance instrumentation

This story focuses on creating the validation/routing stage.
