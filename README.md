# Serverless Cryptography Thesis

This repository contains the implementation and benchmark framework for
a thesis investigating **partial cold start overhead introduced by
cryptographic integrity mechanisms in serverless architectures**.

The system is implemented using **Java 21 + Quarkus** and models a
secure event-processing pipeline built on AWS serverless services
(executed locally via LocalStack for reproducibility).

------------------------------------------------------------------------

## Thesis Goal

The goal of this project is to measure the **application-level cold
start impact** introduced by cryptographic operations in serverless
systems.

Specifically, we measure:

-   JVM / Quarkus initialization overhead
-   Secret retrieval from Secrets Manager
-   Cryptographic key parsing
-   Signing / verification cost
-   Replay protection logic
-   Ledger persistence cost

> Infrastructure-level cold start effects (e.g., container scheduling,
> image pull time) are out of scope.\
> We focus strictly on application-level overhead introduced by security
> mechanisms.

------------------------------------------------------------------------

# System Architecture

The application models a secure event pipeline using:

-   AWS Lambda (Producer + Consumer)
-   SQS (Event transport)
-   DynamoDB (Ledger + Deduplication)
-   AWS Secrets Manager (Key storage)
-   LocalStack (Local reproducible AWS environment)

------------------------------------------------------------------------

## High-Level Flow

    Benchmark Runner (Python)
            |
            v
    Producer Lambda
      - Load key from Secrets Manager
      - Parse key
      - Sign event
            |
            v
    SQS (thesis-events queue)
            |
            v
    Consumer Lambda
      - Load key
      - Verify signature
      - Validate timestamp window
      - Replay protection (DynamoDB conditional write)
      - Write event to ledger
            |
            v
    DynamoDB
      - thesis-dedup (TTL enabled)
      - thesis-ledger

------------------------------------------------------------------------

## Sequence Diagram

``` mermaid
sequenceDiagram
  participant B as Benchmark
  participant P as Producer Lambda
  participant Q as SQS
  participant C as Consumer Lambda
  participant D1 as DynamoDB (Dedup)
  participant D2 as DynamoDB (Ledger)
  participant S as Secrets Manager

  B->>P: Invoke unsigned event
  P->>S: Fetch key
  P->>P: Parse + Sign
  P->>Q: Send signed event
  Q->>C: Trigger
  C->>S: Fetch key
  C->>C: Parse + Verify
  C->>C: Timestamp validation
  C->>D1: Conditional write (dedup)
  C->>D2: Persist to ledger
```

------------------------------------------------------------------------

# Repository Structure

This is a Maven multi-module project:

    serverless-cryptography-thesis/
    │
    ├── commons/                # Shared models (SignedEvent, etc.)
    ├── producer-lambda/        # Event signing Lambda (Quarkus)
    ├── consumer-lambda/        # Verification + replay protection Lambda
    ├── benchmark/              # Python benchmark & attack verification
    ├── .github/
    │   └── overall_implementation_details.md
    └── pom.xml

------------------------------------------------------------------------

# Cryptographic Mechanisms Evaluated

The benchmark evaluates three integrity mechanisms:

-   HMAC-SHA256 (symmetric MAC)
-   RSA-PSS-SHA256 (RSA-2048 signature)
-   ECDSA P-256 + SHA-256

Key material is stored in AWS Secrets Manager and seeded automatically
by the benchmark harness in LocalStack.

For asymmetric algorithms: - Private key → used by Producer - Public key
→ used by Consumer

------------------------------------------------------------------------

# Replay Protection Model

The Consumer enforces replay protection using:

1.  Timestamp validation window
2.  DynamoDB conditional writes keyed by `eventId`
3.  TTL expiration on the dedup table

This ensures: - Tampered payloads are rejected - Replay attacks are
rejected - Expired events are rejected

The benchmark includes an attack verification script to validate this
behavior.

------------------------------------------------------------------------

# Caching & Mitigation Knobs

One of the key experimental variables is key caching:

    thesis.keys.cache.ttlSeconds

-   0 → no caching (baseline)

-   \>0 → cache enabled

This allows measurement of mitigation strategies against cryptographic
cold start overhead.

------------------------------------------------------------------------

# Benchmark Documentation

All benchmark documentation is located in:

    benchmark/README.md

It explains:

-   LocalStack provisioning
-   Cold start methodology
-   Native vs JVM comparisons
-   Algorithm selection
-   Output metrics
-   Attack validation workflow

------------------------------------------------------------------------

# Build Instructions

## JVM Mode

``` bash
mvn clean package -DskipTests
```

## Native Image Mode

``` bash
mvn clean package -DskipTests -Dnative -Dquarkus.native.container-build=true
```

------------------------------------------------------------------------

# Benchmark Quick Start

Install Python dependencies:

``` bash
pip install -r benchmark/requirements.txt
```

Run a cold start benchmark:

``` bash
python benchmark/run_benchmark.py --algorithm HMAC_SHA256 --cold-start
```

See full details in:

    benchmark/README.md

------------------------------------------------------------------------

# Thesis Context

For detailed research framing, measurement model, scope definition, and
implementation decisions, see:

    .github/overall_implementation_details.md

------------------------------------------------------------------------

# Summary

This repository provides:

-   A reproducible secure serverless architecture
-   Multiple cryptographic integrity implementations
-   Replay protection enforcement
-   A full benchmark harness
-   Native vs JVM comparison
-   Cold vs warm measurement support
-   Attack validation tooling

It serves as the experimental platform for evaluating the **performance
cost of cryptographic integrity mechanisms in serverless systems**.
