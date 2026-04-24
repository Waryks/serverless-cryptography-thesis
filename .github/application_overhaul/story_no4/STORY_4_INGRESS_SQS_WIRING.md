# Story 4 — Implement Ingress SQS Wiring

## Goal

Connect the ingress SQS queue to the Validation Lambda using an event source mapping.

This story ensures that events published by the Producer Lambda to:

```text
thesis-ingress-events
```

are automatically delivered to:

```text
thesis-validation
```

without the Validation Lambda manually polling SQS.

---

## Why this story matters

In the AWS Lambda + SQS model, Lambda functions do not usually call `receiveMessage()` themselves.

Instead, AWS manages polling internally through an **event source mapping**:

```text
SQS queue → Lambda trigger
```

This is important because it keeps the system serverless and event-driven.

The Lambda platform is responsible for:

- polling SQS
- batching messages
- invoking the Lambda
- deleting messages after successful processing
- retrying messages after failure

This story creates the infrastructure connection between the ingress queue and the validation stage.

---

## Architecture context

Before this story:

```text
Benchmark Client
   |
   v
Producer Lambda
   |
   v
SQS: thesis-ingress-events
```

After this story:

```text
Benchmark Client
   |
   v
Producer Lambda
   |
   v
SQS: thesis-ingress-events
   |
   v
Validation Lambda
```

---

## Module / script location

This story belongs primarily in the local infrastructure scripts.

Recommended location:

```text
localstack/
├── bootstrap.py
├── reset.py
├── smoke_test.py
└── wiring.py
```

If the project keeps all setup in one script, then this story can extend:

```text
localstack/bootstrap.py
```

---

## Required resources

This story assumes the following already exist:

### Queue

```text
thesis-ingress-events
```

### Lambda

```text
thesis-validation
```

The Lambda implementation may still be a placeholder, but the function should exist in LocalStack before the event source mapping is created.

---

## Event source mapping

Create an event source mapping:

```text
thesis-ingress-events → thesis-validation
```

Configuration:

```text
batch size: 1
enabled: true
```

Batch size should initially be 1 because the thesis experiments focus on one event as one transaction-like unit.

Later experiments may compare batch size 1 versus larger values.

---

## Why batch size 1 initially

Using batch size 1 keeps measurements easier to interpret.

It means:

- one SQS message maps to one Lambda processing unit
- one eventId maps cleanly to one validation result
- retry behavior is easier to reason about
- end-to-end benchmark timing is less ambiguous

This is especially useful while testing crypto, replay protection, and deduplication.

---

## Required script behavior

The script responsible for wiring must:

1. Get the queue URL for `thesis-ingress-events`
2. Get the queue ARN
3. Check whether an event source mapping already exists
4. Create the mapping only if it does not already exist
5. Print the mapping UUID or useful details

The script must be idempotent.

Running it multiple times should not create duplicate mappings.

---

## Conceptual AWS CLI commands

Get queue URL:

```bash
aws --endpoint-url=http://localhost:4566 sqs get-queue-url \
  --queue-name thesis-ingress-events
```

Get queue ARN:

```bash
aws --endpoint-url=http://localhost:4566 sqs get-queue-attributes \
  --queue-url <queue-url> \
  --attribute-names QueueArn
```

Create mapping:

```bash
aws --endpoint-url=http://localhost:4566 lambda create-event-source-mapping \
  --function-name thesis-validation \
  --event-source-arn <queue-arn> \
  --batch-size 1 \
  --enabled
```

List mappings:

```bash
aws --endpoint-url=http://localhost:4566 lambda list-event-source-mappings \
  --function-name thesis-validation
```

---

## Validation Lambda expectations

The Validation Lambda must be prepared to receive an SQS event structure.

The handler should expect:

```text
SQSEvent
```

The event contains:

```text
Records[]
```

Each record contains:

```text
body
```

The body should contain a serialized `SignedEvent`.

The Lambda should not call SQS directly to receive messages.

---

## Retry behavior

The event source mapping controls retry behavior through Lambda success/failure.

If the Validation Lambda:

- returns successfully, the message is deleted from SQS
- throws an exception, the message is retried

This behavior should be considered when designing validation errors later.

For example:

- invalid signature may be routed to rejected queue and not throw
- infrastructure/database errors should throw so the message can be retried

---

## Smoke test expectation

After wiring is complete, a smoke test should be able to:

1. Send a test message to `thesis-ingress-events`
2. Observe that `thesis-validation` is invoked
3. Confirm through logs, output, or downstream placeholder behavior

At this stage, the Validation Lambda can simply log the eventId.

---

## Acceptance criteria

This story is complete when:

1. `thesis-ingress-events` exists.
2. `thesis-validation` Lambda exists.
3. An event source mapping connects the queue to the Lambda.
4. The mapping uses batch size 1.
5. The mapping is enabled.
6. Running the wiring script multiple times does not create duplicates.
7. Sending a message to the ingress queue triggers the Validation Lambda.
8. The Validation Lambda receives an SQS `Records[]` event.

---

## Out of scope

Do not implement yet:

- validation logic
- signature verification
- policy engine
- accepted/rejected routing
- DynamoDB writes
- audit persistence
- benchmark timing

This story only connects the ingress queue to the validation Lambda.
