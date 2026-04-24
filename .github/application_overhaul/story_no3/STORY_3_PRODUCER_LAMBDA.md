# Story 3 — Implement Producer Lambda

## Goal

Implement the Producer Lambda responsible for:

- receiving events from the benchmark client
- generating cryptographic signatures
- publishing signed events to the ingress SQS queue

This is the first component in the secure event-processing pipeline.

---

## Why this story matters

The Producer Lambda is the entry point of the system.

It introduces:

- cryptographic overhead (signing)
- key retrieval overhead (Secrets Manager)
- serialization overhead
- SQS publishing latency

These are critical for measuring partial cold-start and invocation performance.

---

## Module location

```text
producer-lambda/
```

This module should be a Quarkus Lambda project.

Dependencies:

- common (shared event model)
- quarkus-amazon-lambda
- quarkus-amazon-sqs
- quarkus-amazon-secretsmanager
- jackson

---

## Responsibilities

The Producer Lambda must:

1. Receive an input event from the benchmark client
2. Load the appropriate signing key from Secrets Manager
3. Serialize the SignedContent deterministically
4. Generate a signature based on the selected algorithm
5. Encode the signature as Base64
6. Construct a SignedEvent
7. Send the SignedEvent to the ingress SQS queue
8. Return minimal metadata to the caller (eventId, timing, cold start flag)

---

## Input contract

Input will follow the SignedEvent structure, but signature may be empty.

```json
{
  "content": {
    "eventId": "uuid",
    "timestampEpochMs": 123456789,
    "algorithm": "HMAC_SHA256",
    "keyId": "thesis/hmac/current",
    "payload": {
      "nonce": "random"
    }
  },
  "signatureB64": ""
}
```

---

## Output contract

Return a lightweight response:

```json
{
  "eventId": "uuid",
  "coldStart": true,
  "durationMs": 12.34
}
```

---

## Internal components

The module should include:

```text
producer-lambda/
├── handler/
│   └── ProducerHandler.java
├── service/
│   └── ProducerService.java
├── crypto/
│   └── CryptoService.java
├── secrets/
│   └── KeyLoader.java
├── sqs/
│   └── QueuePublisher.java
```

---

## ProducerHandler

Responsibilities:

- entry point for Lambda invocation
- delegate logic to ProducerService
- capture cold start flag
- return response

---

## ProducerService

Responsibilities:

- orchestrate full flow
- call KeyLoader
- call CryptoService
- call QueuePublisher
- measure execution time

---

## KeyLoader

Responsibilities:

- retrieve secret from Secrets Manager using keyId
- return raw key material (string)
- no caching initially

---

## CryptoService

Responsibilities:

- accept algorithm, key material, and byte[] input
- perform signing
- return byte[] signature

Supported algorithms:

- HMAC-SHA256
- RSA-PSS-SHA256
- ECDSA-P256-SHA256

---

## QueuePublisher

Responsibilities:

- serialize SignedEvent to JSON
- send message to:

```text
thesis-ingress-events
```

- use synchronous SQS client

---

## Serialization rules

SignedContent must be serialized deterministically:

- no pretty printing
- stable field order (if possible)
- consistent encoding (UTF-8)

---

## Cold start tracking

Use a static flag:

```text
static boolean firstInvocation
```

Set:

- true for first call
- false for subsequent calls

Return this in response.

---

## Configuration

application.properties must include:

```text
quarkus.sqs.endpoint-override=http://localhost:4566
quarkus.secretsmanager.endpoint-override=http://localhost:4566
```

Queue name:

```text
thesis-ingress-events
```

---

## Acceptance criteria

- Producer Lambda builds successfully
- Lambda can be deployed to LocalStack
- Benchmark or manual invocation works
- Event is sent to SQS queue
- Signature is generated
- Response contains eventId and timing
- Cold start flag is correctly set

---

## Out of scope

- signature verification
- validation logic
- policy engine
- DynamoDB
- audit/rejection handling
- benchmark orchestration (beyond simple invocation)

This story focuses only on producing signed events and publishing them.
