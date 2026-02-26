# Serverless Cryptographic Cold Start Performance

## Project Context

------------------------------------------------------------------------

## 1. Project Overview

This project evaluates **partial cold start latency** in a serverless
architecture using:

-   Java 21
-   Quarkus
-   AWS Lambda
-   SQS
-   DynamoDB
-   Secrets Manager
-   LocalStack (for local testing)

The research focuses on performance overhead introduced by
**cryptographic integrity mechanisms** during partial cold starts.

Full infrastructure cold starts (container scheduling, image pulling,
etc.) are **out of scope**.

------------------------------------------------------------------------

## 2. End-to-End Flow

### Execution Flow

Benchmark Tool (Java) ↓ Producer Lambda (Quarkus) ↓ SQS ↓ Consumer
Lambda (Quarkus) ↓ DynamoDB (Ledger + Replay Protection)

### Detailed Flow

1.  Benchmark invokes Producer Lambda.
2.  Producer:
    -   Retrieves secret (if required)
    -   Parses key
    -   Signs payload
    -   Sends message to SQS
3.  Consumer Lambda receives message from SQS.
4.  Consumer:
    -   Retrieves secret (if required)
    -   Parses key
    -   Verifies signature
    -   Validates timestamp
    -   Checks replay protection
5.  If verification passes → Store event in DynamoDB.

------------------------------------------------------------------------

## 3. Cryptographic Mechanisms Evaluated

1.  HMAC-SHA256 (Symmetric MAC)
2.  RSA-2048 + SHA-256 (Asymmetric Signature)
3.  ECDSA P-256 + SHA-256 (Elliptic Curve Signature)

Each mechanism is evaluated for: - Signing time - Verification time -
Secret retrieval overhead - Key parsing overhead - Cold vs warm
invocation differences

------------------------------------------------------------------------

## 4. Cold Start Scope

### Measured

-   Partial cold start initialization time
-   First invocation latency
-   Warm invocation latency
-   Secret fetch time
-   Key parsing time
-   Signing time
-   Verification time
-   Latency percentiles (P50, P95, P99)

### Not Measured

-   Container provisioning
-   Image pull time
-   Full AWS infrastructure cold start

### Experimental Cold Start Methodology Clarification

To reliably trigger cold executions during benchmarking, the full LocalStack environment (including Lambda runtimes) is restarted between runs. This ensures that each measured “first invocation” occurs in a freshly initialized runtime environment.

However, the research does **not** evaluate full infrastructure cold start (e.g., container scheduling, image pulling, pod orchestration, or host-level provisioning). These infrastructure effects are treated as environmental noise and are not part of the analytical model.

The study instead focuses exclusively on **partial cold start overhead introduced by application-level components under our control**, including:

- Quarkus/JVM initialization within the Lambda runtime
- Secret retrieval from Secrets Manager
- Secret JSON deserialization
- Cryptographic key parsing and object construction
- Signing and verification initialization
- Replay protection logic (timestamp validation + DynamoDB deduplication)

All reported cold start metrics therefore represent *application-level initialization overhead* rather than infrastructure provisioning latency.

------------------------------------------------------------------------

## 5. Mitigation Strategies Evaluated

1.  No caching (baseline)
2.  Secret JSON caching with TTL
3.  Parsed key object caching with TTL
4.  Eager initialization vs Lazy initialization
5.  Single-key vs Dual-key verification (rotation overhead)
6.  JVM mode vs Native Image (GraalVM native build via `--native` flag)
7.  Canonical payload serialization

------------------------------------------------------------------------

## 6. Replay Protection Model

Replay protection uses: - Timestamp validation - DynamoDB eventId
deduplication

Consumer logic: 1. Verify signature 2. Validate timestamp window 3.
Check eventId uniqueness in DynamoDB 4. Reject duplicates

------------------------------------------------------------------------

## 7. Measurement Model

### Black-Box Measurement

End-to-end latency: Benchmark → Producer → SQS → Consumer → DynamoDB

### White-Box Measurement

Internal Lambda timing: - Secret retrieval - Key parsing - Signing -
Verification

------------------------------------------------------------------------

## 8. Core Research Questions

1.  What is the partial cold start overhead introduced by secret
    retrieval and key parsing?
2.  How do HMAC, RSA, and ECDSA differ in cold and warm invocation
    performance?
3.  Which mitigation strategies reduce cold start latency without
    compromising secure rotation and replay protection?

------------------------------------------------------------------------

## 9. Key Design Constraints

The system must allow: - Controlled cold starts - Controlled key
rotation - Reproducible latency measurements - Clear attribution of
performance cost to: - Secret retrieval - Key parsing - Cryptographic
operations

------------------------------------------------------------------------