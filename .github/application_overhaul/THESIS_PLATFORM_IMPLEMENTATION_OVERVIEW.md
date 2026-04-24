# Thesis Platform Implementation Overview

## Title

**Policy-Driven Secure Serverless Event Processing Platform for Evaluating Cryptographic and Cold-Start Performance**

---

## 1. Research Motivation

Modern cloud-native systems increasingly rely on serverless event-driven architectures. In these systems, services communicate through queues, event buses, and asynchronous processing pipelines rather than through long-running servers.

This creates a security challenge: once an event leaves the producing function and enters an asynchronous messaging layer, transport security alone is not enough to prove that the event has not been modified, replayed, or injected by an unauthorized component.

At the same time, serverless platforms are sensitive to cold-start latency. Cryptographic operations, key retrieval, JSON canonicalization, policy loading, and secret parsing may all add latency during the initialization or first invocation path.

This research investigates how cryptographic integrity mechanisms and security enforcement policies affect performance in a serverless event-processing system.

The goal is not to prove that HMAC, RSA, or ECDSA are cryptographically secure. That is already established in existing literature. Instead, this project studies how these mechanisms behave when integrated into a realistic serverless processing pipeline.

---

## 2. Core Research Goal

The project aims to design, implement, and evaluate a secure serverless event-processing platform that supports:

- cryptographic signing and verification
- policy-driven security enforcement
- replay protection
- deduplication
- key rotation
- accepted/rejected event routing
- audit persistence
- performance benchmarking

The research focus is on measuring the impact of these mechanisms on:

- partial cold-start latency
- first invocation latency
- warm invocation latency
- end-to-end event processing latency
- algorithm-specific signing and verification overhead
- key loading and parsing overhead
- policy and routing overhead

---

## 3. What Is Being Measured

The project focuses on **partial cold start**, meaning the part of startup and initialization that is influenced by application code.

### In scope

- Quarkus initialization effects
- CDI bean initialization
- AWS SDK client initialization
- Secrets Manager key retrieval
- key parsing
- signing and verification
- canonical JSON serialization
- DynamoDB access
- SQS publishing and routing
- policy evaluation
- replay/dedup checks

### Out of scope

- AWS platform scheduling latency
- container image download latency
- physical infrastructure provisioning
- cryptographic security proofs
- multi-cloud comparison in this thesis version

Multi-cloud comparison may be a later PhD-level extension.

---

## 4. High-Level System Description

The application is a serverless secure event-processing platform.

A benchmark client generates transaction-like events and invokes a producer Lambda. The producer signs the event and sends it to an ingress SQS queue. A validation Lambda consumes the event, applies a security policy, verifies the signature, checks replay and deduplication rules, and routes the event to either an accepted or rejected queue.

Accepted events are persisted by a persistence Lambda into a ledger table. Rejected events are persisted by an audit Lambda into an audit table.

---

## 5. High-Level Architecture

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
   |                         |
   | accepted                | rejected
   v                         v
SQS: thesis-accepted-events  SQS: thesis-rejected-events
   |                         |
   v                         v
Persistence Lambda           Audit Lambda
   |                         |
   v                         v
DynamoDB: thesis_ledger      DynamoDB: thesis_audit
```

Shared support components:

```text
Secrets Manager
Policy Engine
Key Management / Rotation Logic
Canonicalization Logic
Benchmark Runner
DynamoDB Dedup Table
```

---

## 6. Main Components

### 6.1 Benchmark Client

The benchmark client is responsible for generating test events and invoking the producer Lambda.

It should support configurable variables such as:

- algorithm
- payload size
- number of requests
- concurrency
- policy mode
- replay mode
- key cache mode
- wait-for-completion mode

It should record:

- producer invocation latency
- end-to-end latency
- accepted/rejected outcome
- cold-start markers
- percentile statistics

---

### 6.2 Producer Lambda

The producer Lambda receives an unsigned or partially prepared event from the benchmark client.

Responsibilities:

- receive event input
- load signing key from Secrets Manager
- serialize signed content deterministically
- sign the event based on selected algorithm
- attach signature
- publish signed event to ingress queue
- return eventId and basic timing information

The producer is the first place where cryptographic overhead is introduced.

---

### 6.3 Ingress Queue

The ingress queue stores signed events before validation.

Queue name:

```text
thesis-ingress-events
```

Purpose:

- decouple producer and validator
- simulate asynchronous event-driven architecture
- allow Lambda event source mapping to trigger validation

---

### 6.4 Validation Lambda

The validation Lambda is the core security enforcement component.

Responsibilities:

- consume events from ingress queue
- deserialize event
- load applicable security policy
- load verification key or keys
- verify signature
- check replay window if enabled
- check deduplication if enabled
- support current/previous key validation during rotation
- route accepted events to accepted queue
- route rejected events to rejected queue

This Lambda contains most of the security decision logic.

---

### 6.5 Policy Engine

The policy engine controls how an event is validated.

A security policy may define:

- policyId
- required algorithm
- replay check enabled/disabled
- replay window duration
- deduplication enabled/disabled
- previous key allowed/denied
- strict or relaxed validation behavior

The policy engine makes the platform configurable and allows experiments to compare different security configurations.

---

### 6.6 Key Management Subsystem

The key management subsystem loads cryptographic material from Secrets Manager.

It should support:

- current key
- previous key
- key metadata
- algorithm compatibility checks
- optional cache TTL
- parsed key caching
- rotation experiments

Secrets should be stored using the prefix:

```text
thesis/<algorithm>/<stage>
```

Examples:

```text
thesis/hmac/current
thesis/hmac/previous
thesis/rsa/current
thesis/rsa/previous
thesis/ecdsa/current
thesis/ecdsa/previous
```

A secret value may contain:

```json
{
  "keyId": "rsa-2026-01",
  "algorithm": "RSA_PSS_SHA256",
  "keyMaterial": "..."
}
```

---

### 6.7 Accepted Queue

Accepted events are events that passed validation.

Queue name:

```text
thesis-accepted-events
```

Purpose:

- separate valid business events from validation logic
- allow persistence to be handled independently
- enable measurement of multi-stage latency

---

### 6.8 Rejected Queue

Rejected events are events that failed validation.

Queue name:

```text
thesis-rejected-events
```

Purpose:

- preserve rejected events for audit
- avoid silently dropping invalid events
- support analysis of invalid signature, replay, expiry, or unknown key scenarios

---

### 6.9 Persistence Lambda

The persistence Lambda consumes accepted events and writes them to the ledger table.

Responsibilities:

- consume accepted events
- write final accepted record to DynamoDB
- store algorithm, keyId, timestamp, and processing metadata
- provide a completion signal for the benchmark client

---

### 6.10 Audit Lambda

The audit Lambda consumes rejected events and writes audit records.

Responsibilities:

- consume rejected events
- store rejection reason
- store event metadata
- store policy and algorithm information
- support benchmark observation of rejected scenarios

---

### 6.11 DynamoDB Tables

#### thesis_ledger

Stores accepted events.

Purpose:

- final successful business state
- benchmark completion signal
- accepted event history

#### thesis_dedup

Stores processed event IDs.

Purpose:

- prevent duplicate processing
- defend against replay or at-least-once delivery duplicates

#### thesis_audit

Stores rejected events and security decisions.

Purpose:

- auditability
- debugging
- rejected path measurement
- security validation evidence

---

## 7. Event Model

The event model separates signed data from the signature itself.

### SignedEvent

```java
SignedEvent {
    SignedContent content;
    String signatureB64;
}
```

### SignedContent

```java
SignedContent {
    String eventId;
    long timestampEpochMs;
    Algorithm algorithm;
    String keyId;
    JsonNode payload;
}
```

The system signs the deterministic serialized representation of `SignedContent`.

This means the following fields are protected by the signature:

- eventId
- timestamp
- algorithm
- keyId
- payload

The signature itself is not included in the signed bytes.

---

## 8. Supported Algorithms

The platform should support:

- HMAC-SHA256
- RSA-PSS-SHA256
- ECDSA-P256-SHA256

These algorithms represent different trust and performance profiles:

- HMAC is symmetric and fast
- RSA-PSS is asymmetric and widely used
- ECDSA uses smaller keys/signatures and is common in modern systems

---

## 9. Validation Decision Flow

```text
Receive event
   |
   v
Deserialize
   |
   v
Load policy
   |
   v
Load key material
   |
   v
Verify signature
   |
   +-- invalid --> rejected queue
   |
   v
Replay check
   |
   +-- expired --> rejected queue
   |
   v
Dedup check
   |
   +-- duplicate --> rejected queue
   |
   v
Accepted queue
```

---

## 10. Key Rotation Flow

```text
Load current key
   |
   v
Try verification
   |
   +-- success --> accepted
   |
   v
If policy allows previous key
   |
   v
Load previous key
   |
   v
Try verification
   |
   +-- success --> accepted during grace period
   |
   v
Reject
```

---

## 11. Benchmarking Goals

The benchmark should support both simple and full end-to-end modes.

### Producer-only benchmark

Measures:

- Lambda invoke time
- key loading time
- signing time
- SQS publish time

### End-to-end benchmark

Measures:

- benchmark invoke start
- producer completion
- ingress queue delay
- validation latency
- routing latency
- persistence/audit latency
- final DynamoDB observation time

---

## 12. Research Questions

Possible final research questions:

1. What is the latency overhead of cryptographic signing and verification in a serverless event-processing platform?

2. How do HMAC-SHA256, RSA-PSS-SHA256, and ECDSA-P256-SHA256 differ in cold-start and warm invocation performance?

3. What is the performance impact of key retrieval, key parsing, and key rotation support?

4. How much overhead is introduced by policy-driven validation, replay protection, deduplication, and audit routing?

5. Is a multi-stage serverless security pipeline viable for transaction-like event processing under cold-start-sensitive conditions?

---

## 13. Why This Application Is Complex Enough for a Thesis

The final system is not just a queue demo.

It includes:

- multiple Lambdas
- multiple SQS queues
- multiple DynamoDB tables
- Secrets Manager integration
- cryptographic signing and verification
- key rotation logic
- policy-driven validation
- accepted/rejected routing
- audit persistence
- benchmark orchestration
- cold-start-aware evaluation

This creates meaningful code complexity while staying focused on the research question.

---

## 14. Implementation Strategy

The system should be implemented incrementally.

Recommended order:

1. Base producer to ingress queue to validation pipeline
2. Real cryptographic signing and verification
3. Policy engine
4. Key rotation support
5. Accepted/rejected routing
6. Persistence and audit Lambdas
7. DynamoDB dedup and ledger logic
8. Benchmark runner
9. Cold-start experiment automation
10. Final evaluation and result collection

---

## 15. Future Work

This architecture can later be extended into a PhD topic by comparing equivalent secure event-processing platforms across:

- AWS Lambda + SQS + DynamoDB + Secrets Manager
- Azure Functions + Service Bus + Cosmos DB / Table Storage + Key Vault
- Google Cloud Functions / Cloud Run + Pub/Sub + Firestore + Secret Manager

The master’s thesis focuses on AWS only to keep the scope manageable while building a sufficiently complex and measurable platform.

---

## 16. Summary

The project evolves from a simple signed-message queue prototype into a policy-driven secure serverless event-processing platform.

The final application is complex enough to demonstrate software engineering depth, while the evaluation remains focused on the original research objective: understanding the performance impact of cryptographic security mechanisms and related controls in cold-start-sensitive serverless systems.
