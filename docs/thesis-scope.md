# Thesis Scope and Implementation Overview

## Purpose

This document summarizes the research scope, system boundaries, and the implemented serverless platform used by the thesis project.

## Research Scope

The project evaluates the application-level cold-start overhead introduced by cryptographic integrity mechanisms in a serverless event-processing pipeline.

### In scope

- Quarkus and JVM initialization cost
- Secrets Manager key retrieval and parsing
- Cryptographic signing and verification
- Policy evaluation
- Replay protection and deduplication
- Accepted/rejected routing
- Ledger and audit persistence
- Benchmark orchestration and result collection

### Out of scope

- AWS infrastructure scheduling latency
- Container image pull time
- Physical provisioning delays
- Cryptographic proof analysis
- Multi-cloud comparisons

## System Overview

The implemented platform follows this flow:

1. A benchmark runner generates events and invokes the producer Lambda.
2. The producer signs the event and publishes it to the ingress queue.
3. The validation Lambda verifies the event, applies the policy, and checks replay/deduplication rules.
4. Accepted events are persisted to the ledger table.
5. Rejected events are persisted to the audit table.

## Main Components

- `producer-lambda/` — signs and publishes events
- `validation-lambda/` — verifies signatures and applies security policy
- `persistence-lambda/` — stores accepted events
- `audit-lambda/` — stores rejected events
- `benchmark/` — experiment runner and benchmark scenarios
- `localstack/` — local AWS-compatible test environment

## Related Documentation

- `README.md` — project entry point and implementation summary
- `benchmark/README.md` — benchmark runner documentation
- `localstack/README.md` — LocalStack provisioning and reset details

