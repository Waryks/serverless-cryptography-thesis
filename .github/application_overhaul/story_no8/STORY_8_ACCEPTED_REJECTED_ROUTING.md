# Story 8 — Implement Accepted and Rejected Event Routing

## Goal

Implement a dedicated routing subsystem that separates valid events from rejected events after validation.

The Validation Lambda should no longer simply accept or reject internally. Instead, it should publish events to dedicated downstream queues:

- accepted events
- rejected events

This creates a multi-stage event-processing architecture and introduces operational separation between successful and failed processing paths.

---

## Why this story matters

This story is one of the most important architectural transitions in the platform.

Before this story, the Validation Lambda behaves mostly like:

```text
consume → validate → end
```

After this story, the platform becomes:

```text
consume → validate → route → downstream processing
```

This transforms the application from a simple validation demo into a real event-processing platform.

It also introduces meaningful architectural complexity for the thesis because:

- accepted events follow a business processing path
- rejected events follow a security/audit path
- latency now includes routing stages
- multiple downstream Lambdas can process different outcomes independently

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
   |                         |
   | accepted                | rejected
   v                         v
Accepted Queue               Rejected Queue
```

Future stories will add:

```text
Accepted Queue  → Persistence Lambda
Rejected Queue  → Audit Lambda
```

---

## Queue responsibilities

### Accepted queue

Queue name:

```text
thesis-accepted-events
```

Purpose:

- carry validated business events
- decouple validation from persistence
- support downstream ledger persistence
- support end-to-end latency measurement

---

### Rejected queue

Queue name:

```text
thesis-rejected-events
```

Purpose:

- preserve rejected events
- support audit logging
- support debugging and observability
- prevent silent event loss
- support rejection benchmarking

---

## Module location

Routing logic should primarily live inside:

```text
validation-lambda/
```

Recommended package structure:

```text
validation-lambda/
└── src/main/java/com/alexthesis/validation/routing/
    ├── ValidationRouter.java
    ├── AcceptedPublisher.java
    ├── RejectedPublisher.java
    ├── RoutingDecision.java
    └── QueueResolver.java
```

Keep the first implementation simple.

---

## High-level routing flow

Conceptual flow:

```text
receive SignedEvent
   ↓
validate
   ↓
decision
   ↓
accepted? ─── yes ───→ accepted queue
   |
   no
   ↓
rejected queue
```

The Validation Lambda should become responsible for routing decisions rather than final business persistence.

---

## Accepted routing behavior

If validation succeeds:

- publish original `SignedEvent`
- send to:

```text
thesis-accepted-events
```

The accepted route should preserve the original signed event without modification.

Reason:

- downstream persistence should store the original trusted event
- benchmark should measure complete validated event flow
- auditability of accepted events should remain possible

---

## Rejected routing behavior

If validation fails:

- construct a `RejectedEvent`
- publish to:

```text
thesis-rejected-events
```

The rejected event should include:

- original event if available
- rejection reason
- descriptive message
- rejection timestamp

---

## RejectedEvent responsibilities

The `RejectedEvent` model becomes more important after this story.

Purpose:

- preserve security failures
- provide context for audit persistence
- support debugging
- support benchmark analysis

Example rejection causes:

- invalid signature
- expired event
- replay detected
- unknown key
- algorithm mismatch
- deserialization failure

---

## RoutingDecision model

The Validation Lambda should avoid scattered boolean checks such as:

```text
if valid
if invalid
```

Instead, introduce a structured routing decision.

Suggested conceptual structure:

```text
decision type
reason
message
route target
```

Purpose:

- centralize routing behavior
- improve readability
- simplify future policy integration

---

## Queue publishing behavior

The router should use SQS publishing services.

Requirements:

- synchronous publishing
- queue URL caching
- JSON serialization through Jackson
- no direct business logic inside publishers

The routing layer should focus only on:

```text
which queue receives which message
```

---

## Queue resolution

Queue URLs should be resolved dynamically from queue names.

Suggested configuration:

```text
thesis.sqs.accepted-queue-name=thesis-accepted-events
thesis.sqs.rejected-queue-name=thesis-rejected-events
```

The system should cache queue URLs after first resolution.

---

## Error handling behavior

Routing introduces new infrastructure failure scenarios.

Examples:

- accepted queue unavailable
- rejected queue unavailable
- serialization failure
- SQS publish failure

Behavior:

### Security rejection

If validation fails:

```text
publish rejected event
do not throw
```

### Infrastructure failure

If routing fails:

```text
throw exception
allow SQS retry
```

This distinction is critical.

Rejected events should not retry forever simply because they are invalid.

However, infrastructure failures should retry because the system could not safely persist the outcome.

---

## Multi-stage architecture impact

This story introduces true downstream event flow.

The platform now becomes:

```text
validation stage
↓
routing stage
↓
persistence/audit stage
```

This is important for the thesis because it allows experiments such as:

- validation-only latency
- routing overhead
- accepted vs rejected processing cost
- downstream persistence overhead
- queue fan-out effects

---

## Benchmark implications

The benchmark should later be able to measure:

### Accepted path

```text
Producer
→ Validation
→ Accepted Queue
→ Persistence
```

### Rejected path

```text
Producer
→ Validation
→ Rejected Queue
→ Audit
```

This enables richer performance analysis.

---

## Smoke test expectations

A smoke test should be able to:

### Accepted scenario

1. Send a valid event
2. Observe event in:

```text
thesis-accepted-events
```

---

### Rejected scenario

1. Send invalid event
2. Observe event in:

```text
thesis-rejected-events
```

---

## Logging expectations

The Validation Lambda should log routing decisions clearly.

Examples:

```text
eventId=123 routed=ACCEPTED
```

```text
eventId=456 routed=REJECTED reason=INVALID_SIGNATURE
```

These logs are useful during benchmark debugging.

---

## Acceptance criteria

This story is complete when:

1. Validation Lambda routes valid events to `thesis-accepted-events`.
2. Validation Lambda routes rejected events to `thesis-rejected-events`.
3. Accepted route preserves original `SignedEvent`.
4. Rejected route publishes `RejectedEvent`.
5. Queue URL resolution exists.
6. Queue URL caching exists.
7. Security rejection does not throw.
8. Infrastructure failure throws.
9. Routing logic is separated from validation logic.
10. Smoke tests can observe both accepted and rejected flows.

---

## Out of scope

Do not implement yet:

- Persistence Lambda
- Audit Lambda
- final DynamoDB persistence
- benchmark orchestration
- DLQs
- advanced fan-out architectures
- SNS/EventBridge integration

This story focuses only on routing validation outcomes into dedicated processing paths.
