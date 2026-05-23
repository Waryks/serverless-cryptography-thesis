# Agent Verification Plan — Story Implementation, Wiring, LocalStack, and Tests

## Purpose

This document instructs an implementation agent to review the project after the 15 core stories have been implemented.

The agent must verify:

- which story requirements are implemented
- what is still missing
- what infrastructure still needs wiring
- whether LocalStack execution works end-to-end
- whether each module has the correct tests
- whether test scope stays inside module boundaries

This document is not a feature story. It is a verification and hardening checklist.

---

## Core rule for tests

Each module must test its own responsibilities.

Do not create cross-module tests inside individual modules.

Cross-module behavior should be tested only through:

- LocalStack smoke tests
- LocalStack integration tests
- benchmark/orchestration tests

---

## Test pattern

Each module should follow this pattern:

```text
unit tests
contract tests if needed
integration tests
```

### Unit tests

Unit tests validate isolated logic without AWS services.

Examples:

- event model serialization
- crypto helpers
- policy decisions
- replay checker
- mapper behavior
- routing decision logic

### Contract tests

Contract tests are needed when a module consumes or produces shared message formats.

Use contract tests for:

- SignedEvent JSON format
- RejectedEvent JSON format
- LedgerRecord format
- AuditRecord format
- SQS message body expectations

Contract tests should prevent accidental schema drift.

### Integration tests

Integration tests validate that the module works with its external dependencies.

Examples:

- SQS publishing works against LocalStack
- DynamoDB writes work against LocalStack
- Secrets Manager key loading works against LocalStack
- Lambda handler can process representative event input

Integration tests should stay module-local when possible.

Full pipeline testing belongs in LocalStack end-to-end scripts, not inside one module.

---

# Section 1 — Story implementation audit

The agent must review the project against each story.

For every story, produce a status:

```text
IMPLEMENTED
PARTIALLY_IMPLEMENTED
MISSING
NEEDS_REWORK
```

Also list:

- implemented files
- missing files
- missing configuration
- missing tests
- risks

---

## Story 1 — Base LocalStack Environment

Verify:

- `docker-compose.yml` exists
- LocalStack starts with required services
- bootstrap script exists
- reset script exists
- smoke test script exists
- queues are created
- DynamoDB tables are created
- Secrets Manager secrets are created
- scripts are idempotent

Required resources:

```text
Queues:
- thesis-ingress-events
- thesis-accepted-events
- thesis-rejected-events

Tables:
- thesis_ledger
- thesis_dedup
- thesis_audit

Secrets:
- thesis/hmac/current
- thesis/hmac/previous
- thesis/rsa/current
- thesis/rsa/previous
- thesis/ecdsa/current
- thesis/ecdsa/previous
```

Check whether bootstrap also deploys Lambdas and creates mappings.

If not, identify what still needs wiring.

---

## Story 2 — Core Event Model

Verify in `common`:

- Algorithm enum exists
- SignedContent exists
- SignedEvent exists
- RejectedEvent exists
- AuditReason exists
- records serialize/deserialize with Jackson
- signature boundary is documented

Check contract tests for:

- SignedEvent JSON
- SignedContent JSON
- RejectedEvent JSON
- enum serialization

---

## Story 3 — Producer Lambda

Verify:

- ProducerHandler exists
- ProducerService exists
- queue publisher exists
- key loading exists
- signing exists
- SQS publish to ingress queue works
- response includes eventId, duration, coldStart
- LocalStack invoke works

Check tests:

- unit tests for ProducerService orchestration
- unit tests for signing decision logic
- integration test for SQS publish
- integration test for Secrets Manager loading

---

## Story 4 — Ingress SQS Wiring

Verify:

- event source mapping exists:

```text
thesis-ingress-events → thesis-validation
```

- batch size is 1
- mapping is enabled
- wiring script is idempotent
- validation Lambda receives SQSEvent Records

Check LocalStack commands/scripts for:

- get queue ARN
- create mapping
- list existing mappings
- avoid duplicate mappings

---

## Story 5 — Validation Lambda

Verify:

- ValidationHandler exists
- ValidationService exists
- SQSEvent parsing works
- SignedEvent deserialization works
- basic validation exists
- signature verification exists or is clearly TODO
- replay check is connected
- dedup check is connected
- accepted routing exists
- rejected routing exists
- security failures do not throw
- infrastructure failures throw

Check tests:

- unit tests for ValidationService decisions
- unit tests for invalid event handling
- integration tests for SQS input handling
- integration tests for routing output

---

## Story 6 — Policy Engine

Verify:

- SecurityPolicy exists
- PolicyLoader or equivalent exists
- PolicyResolver or equivalent exists
- policy controls algorithm compatibility
- policy controls replay enabled/disabled
- policy controls replay window
- policy controls dedup enabled/disabled
- policy controls previous-key support
- policy is configurable without Java code changes

Check tests:

- unit tests for policy resolution
- unit tests for algorithm mismatch
- unit tests for replay/dedup toggles
- contract tests if policy is loaded from YAML/JSON

---

## Story 7 — Key Management and Rotation

Verify:

- key secret JSON format is supported
- current key can be loaded
- previous key can be loaded
- key material can be parsed
- HMAC key support exists
- RSA key support exists
- ECDSA key support exists
- optional cache exists
- cache TTL is configurable
- rotation-aware verification exists
- algorithm/key compatibility checks exist

Check tests:

- unit tests for key parsing
- unit tests for secret JSON parsing
- unit tests for cache hit/miss
- unit tests for current/previous resolution
- integration tests for Secrets Manager loading

---

## Story 8 — Accepted and Rejected Routing

Verify:

- Validation Lambda publishes accepted events to:

```text
thesis-accepted-events
```

- Validation Lambda publishes rejected events to:

```text
thesis-rejected-events
```

- accepted route preserves original SignedEvent
- rejected route creates RejectedEvent
- queue URLs are resolved from queue names
- queue URL caching exists
- routing failures throw
- security rejection routing does not throw

Check tests:

- unit tests for routing decisions
- unit tests for RejectedEvent creation
- integration tests for accepted SQS publish
- integration tests for rejected SQS publish

---

## Story 9 — Persistence Lambda

Verify:

- PersistenceHandler exists
- PersistenceService exists
- LedgerRepository exists
- LedgerRecord model exists
- accepted SQSEvent input is parsed
- SignedEvent maps to ledger record
- DynamoDB write to `thesis_ledger` works
- event source mapping exists:

```text
thesis-accepted-events → thesis-persistence
```

Check tests:

- unit tests for LedgerMapper
- unit tests for PersistenceService
- integration tests for DynamoDB write
- integration tests for SQSEvent handler input

---

## Story 10 — Audit Lambda

Verify:

- AuditHandler exists
- AuditService exists
- AuditRepository exists
- AuditRecord model exists
- rejected SQSEvent input is parsed
- RejectedEvent maps to audit record
- DynamoDB write to `thesis_audit` works
- event source mapping exists:

```text
thesis-rejected-events → thesis-audit
```

Check tests:

- unit tests for AuditMapper
- unit tests for AuditService
- integration tests for DynamoDB write
- integration tests for SQSEvent handler input

---

## Story 11 — Deduplication and Replay Protection

Verify:

- replay checker exists
- replay window is configurable
- expired events are rejected
- dedup store exists
- `thesis_dedup` is used
- duplicate eventId is rejected
- dedup integrates with policy engine
- dedup integrates with rejected routing
- infrastructure failures throw

Check tests:

- unit tests for replay checker
- unit tests for dedup decision logic
- integration tests for DynamoDB dedup record
- scenario test for duplicate event

---

## Story 12 — Benchmark Runner

Verify:

- benchmark runner exists
- events are generated by benchmark
- producer Lambda is invoked by benchmark
- benchmark can wait for ledger result
- benchmark can wait for audit result
- CSV or JSON output exists
- latency metrics are calculated
- accepted scenario exists
- rejected scenario exists

Check tests:

- unit tests for event generator
- unit tests for percentile/statistics logic
- integration test against LocalStack for single accepted flow
- integration test against LocalStack for single rejected flow

---

## Story 13 — Performance Instrumentation

Verify:

- timing utility exists
- timing stages exist
- producer timings exist
- validation timings exist
- persistence timings exist
- audit timings exist
- cold start tracking exists
- timings use `System.nanoTime()`
- timings are exported/logged consistently

Check tests:

- unit tests for timing utility
- unit tests for cold start tracker
- unit tests for timing snapshot serialization
- contract tests if timing metadata is stored in ledger/audit

---

## Story 14 — Experiment Configuration and Scenario System

Verify:

- YAML/JSON scenario config exists
- scenario loader exists
- scenario validator exists
- scenario executor exists
- accepted/rejected expected outcomes are validated
- algorithm is configurable
- payload size is configurable
- replay/dedup/cache settings are configurable
- cold/warm execution modes are configurable

Check tests:

- unit tests for config parsing
- unit tests for invalid config rejection
- unit tests for expected outcome validation
- contract tests for scenario schema if needed

---

## Story 15 — Security Validation and Failure Injection

Verify scenarios exist for:

- invalid signature
- expired event
- duplicate event
- unknown key
- algorithm mismatch
- malformed payload
- infrastructure failure

Verify expected behavior:

- invalid security events go to audit
- accepted events go to ledger
- infrastructure failures retry
- security failures do not retry forever

Check tests:

- integration test for invalid signature
- integration test for expired event
- integration test for duplicate event
- integration test for malformed payload
- integration test for unknown key

---

# Section 2 — LocalStack wiring audit

The agent must verify all local infrastructure wiring.

## Required queues

```text
thesis-ingress-events
thesis-accepted-events
thesis-rejected-events
```

## Required Lambda functions

```text
thesis-producer
thesis-validation
thesis-persistence
thesis-audit
```

## Required event source mappings

```text
thesis-ingress-events  → thesis-validation
thesis-accepted-events → thesis-persistence
thesis-rejected-events → thesis-audit
```

All mappings should use:

```text
batch size = 1
enabled = true
```

## Required tables

```text
thesis_ledger
thesis_dedup
thesis_audit
```

## Required secrets

```text
thesis/hmac/current
thesis/hmac/previous
thesis/rsa/current
thesis/rsa/previous
thesis/ecdsa/current
thesis/ecdsa/previous
```

---

# Section 3 — End-to-end LocalStack smoke tests

The agent must ensure scripts exist for the following smoke tests.

## Smoke Test 1 — Accepted flow

Expected flow:

```text
benchmark/test event
→ thesis-producer
→ thesis-ingress-events
→ thesis-validation
→ thesis-accepted-events
→ thesis-persistence
→ thesis_ledger
```

Expected result:

```text
ledger record exists
audit record absent
```

---

## Smoke Test 2 — Invalid signature flow

Expected flow:

```text
invalid event
→ validation
→ rejected queue
→ audit lambda
→ thesis_audit
```

Expected result:

```text
audit record exists with INVALID_SIGNATURE
ledger record absent
```

---

## Smoke Test 3 — Expired event flow

Expected result:

```text
audit record exists with EXPIRED
```

---

## Smoke Test 4 — Duplicate event flow

Expected result:

```text
first event accepted
second event rejected with REPLAY_DETECTED
```

---

## Smoke Test 5 — Unknown key flow

Expected result:

```text
audit record exists with UNKNOWN_KEY
```

---

# Section 4 — Module test expectations

## common

Unit tests:

- event model construction
- enum behavior
- serialization/deserialization

Contract tests:

- SignedEvent JSON
- RejectedEvent JSON

Integration tests:

- not required unless common has external dependencies

---

## producer-lambda

Unit tests:

- signing orchestration
- response creation
- cold start tracker

Integration tests:

- Secrets Manager load
- SQS publish

No cross-module tests.

---

## validation-lambda

Unit tests:

- validation decisions
- policy decisions
- replay checker
- dedup checker
- routing decisions

Integration tests:

- SQS event handler input
- Secrets Manager load
- DynamoDB dedup
- SQS accepted/rejected publish

No Persistence or Audit assertions inside validation module tests.

---

## persistence-lambda

Unit tests:

- ledger mapping
- service orchestration

Integration tests:

- DynamoDB write
- SQS handler input

No producer/validation tests here.

---

## audit-lambda

Unit tests:

- audit mapping
- service orchestration

Integration tests:

- DynamoDB write
- SQS handler input

No validation assertions here.

---

## benchmark

Unit tests:

- event generation
- scenario parsing
- metrics calculation
- expected outcome validation

Integration tests:

- one accepted LocalStack flow
- one rejected LocalStack flow

Benchmark may perform cross-module LocalStack tests because it is the orchestration layer.

---

# Section 5 — Final agent output required

After checking the project, the agent must produce a report with this structure:

```text
1. Story implementation status table
2. Missing implementation items
3. Missing wiring items
4. Missing LocalStack resources
5. Missing unit tests
6. Missing contract tests
7. Missing integration tests
8. Smoke test results
9. Recommended next fixes in priority order
```

The agent should not rewrite major architecture unless necessary.

The goal is to finish wiring, testing, and validation of the 15-story platform.
