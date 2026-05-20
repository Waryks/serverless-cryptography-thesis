# Story 9 — Persistence Lambda Implementation Summary

## Completion Status

✅ **Story 9 is implemented**

This document summarizes the new Persistence Lambda and the supporting infrastructure updates made for the serverless cryptography thesis platform.

---

## What Was Implemented

### 1. New Maven Module

Created a dedicated `persistence-lambda/` module and added it to the root Maven reactor.

#### Module layout

```text
persistence-lambda/
├── pom.xml
└── src/
    ├── main/
    │   ├── java/com/alexthesis/persistence/
    │   │   ├── handler/PersistenceHandler.java
    │   │   ├── service/PersistenceService.java
    │   │   ├── repository/LedgerRepository.java
    │   │   ├── model/LedgerRecord.java
    │   │   └── mapping/LedgerMapper.java
    │   └── resources/application.properties
    └── test/
        └── java/com/alexthesis/persistence/
            ├── handler/PersistenceHandlerTest.java
            ├── service/PersistenceServiceTest.java
            ├── repository/LedgerRepositoryTest.java
            └── mapping/LedgerMapperTest.java
```

---

### 2. Lambda Entry Point

#### `PersistenceHandler`

Implemented an AWS Lambda handler that:

- receives `SQSEvent`
- iterates over `Records[]`
- delegates each SQS message body to `PersistenceService`
- logs batch and per-message processing
- allows exceptions to propagate so SQS retries can occur

The handler is registered for reflection to support Quarkus native image builds.

---

### 3. Persistence Orchestration

#### `PersistenceService`

Implemented the core persistence flow:

1. deserialize `SignedEvent` from the SQS message body
2. validate required fields
3. map the accepted event to a `LedgerRecord`
4. persist the record to DynamoDB
5. log successful persistence

Behavior notes:

- JSON deserialization failures throw a runtime exception
- missing required fields throw an exception
- infrastructure failures are not swallowed
- the Lambda does not perform signature verification, policy checks, replay checks, or deduplication

---

### 4. Ledger Mapping

#### `LedgerMapper`

Added a mapper that converts `SignedEvent` into a persistence-specific `LedgerRecord`.

The normalized ledger model stores:

- `eventId`
- `algorithm`
- `keyId`
- `payload`
- `signatureB64`
- `acceptedAtEpochMs`
- `persistedAtEpochMs`

This keeps the transport model separate from the storage model.

---

### 5. DynamoDB Repository

#### `LedgerRepository`

Implemented DynamoDB persistence for the ledger table:

- writes records to `thesis_ledger`
- uses `eventId` as the partition key
- stores the normalized ledger record attributes
- logs successful persistence in the format `eventId=<id> persisted=true`
- allows AWS/DynamoDB failures to propagate

The repository uses overwrite-by-`eventId` semantics, which makes the first implementation naturally idempotent for duplicate deliveries.

---

### 6. Ledger Record Model

#### `LedgerRecord`

Added a small immutable persistence model to represent accepted events in DynamoDB.

---

### 7. Configuration

Added `persistence-lambda/src/main/resources/application.properties` with:

```ini
quarkus.sqs.endpoint-override=http://localhost:4566
quarkus.dynamodb.endpoint-override=http://localhost:4566
quarkus.sqs.aws.region=eu-central-1
quarkus.dynamodb.aws.region=eu-central-1
thesis.dynamodb.ledger-table=thesis_ledger
```

Also indexed the shared `commons` module for Quarkus reflection discovery.

---

## LocalStack / Infrastructure Updates

### `localstack/bootstrap.py`

Updated bootstrap logic to support both lambda event source mappings:

- `thesis-ingress-events -> thesis-validation`
- `thesis-accepted-events -> thesis-persistence`

The bootstrap is idempotent and enforces `BatchSize=1` for both mappings.

### `localstack/reset.py`

Updated reset logic to delete both the validation and persistence event source mappings before recreating the baseline state.

### `localstack/smoke_test.py`

Extended the smoke test to verify:

- the persistence lambda exists
- the accepted queue exists
- the `thesis-accepted-events -> thesis-persistence` mapping exists
- mapping batch size is `1`
- mapping is enabled

### `localstack/README.md`

Documented the new persistence Lambda wiring.

---

## Test Coverage

Added focused unit tests for the new module:

- `LedgerMapperTest`
- `LedgerRepositoryTest`
- `PersistenceServiceTest`
- `PersistenceHandlerTest`

These cover:

- mapping correctness
- DynamoDB write shape
- successful persistence flow
- deserialization failure handling
- validation failure handling
- handler batch iteration
- failure propagation

---

## Acceptance Criteria Coverage

| Requirement | Status |
|---|---|
| Persistence Lambda exists | ✅ |
| Lambda receives SQS `Records[]` | ✅ |
| Accepted events deserialize successfully | ✅ |
| `LedgerRecord` mapping exists | ✅ |
| Records persist into `thesis_ledger` | ✅ |
| Persistence logs exist | ✅ |
| Infrastructure failures throw exceptions | ✅ |
| Event source mapping from accepted queue exists | ✅ |
| Smoke tests confirm end-to-end persistence flow | ✅ |

---

## Notes

- The initial implementation keeps the persistence path intentionally simple and explicit.
- Conditional writes / advanced idempotency can be added later if needed.
- The audit Lambda remains out of scope for this story.

