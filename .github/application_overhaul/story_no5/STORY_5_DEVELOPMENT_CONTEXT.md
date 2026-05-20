# Story 5 — Development Context for Next Stories

## Current State

The validation-lambda module is **implemented and fully compiled**.

All source files are in place:
- Handler: `ValidationHandler.java`
- Service: `ValidationService.java`, `ValidationDecision.java`
- Crypto: `SignatureVerifier.java`, `SecretService.java`
- Checks: `ReplayChecker.java`, `DedupStore.java`
- Routing: `ValidationRouter.java`
- Tests: `ValidationServiceTest.java`

The parent `pom.xml` has been updated to include `validation-lambda` in the module list.

---

## Build Artifacts

After running `mvn clean package`, the following artifacts are produced:

```
validation-lambda/target/validation-lambda-0.1.0.jar
validation-lambda/target/validation-lambda-0.1.0-runner.jar
```

The `-runner.jar` is the Quarkus packaged artifact suitable for AWS Lambda deployment.

---

## Configuration Contract

### Application Properties

The validation-lambda respects these configuration properties:

```properties
# SQS queues
thesis.sqs.ingress-queue-name=thesis-ingress-events
thesis.sqs.accepted-queue-name=thesis-accepted-events
thesis.sqs.rejected-queue-name=thesis-rejected-events

# DynamoDB
thesis.dynamodb.dedup-table=thesis-dedup
thesis.dynamodb.dedup-ttl-seconds=86400

# Security features
thesis.security.replay-check-enabled=true
thesis.security.replay-window-ms=300000
thesis.security.dedup-enabled=true

# Key caching
thesis.keys.cache.ttlSeconds=0

# AWS service endpoints
quarkus.sqs.endpoint-override=http://localhost:4566
quarkus.secretsmanager.endpoint-override=http://localhost:4566
quarkus.dynamodb.endpoint-override=http://localhost:4566
```

---

## Lambda Handler Contract

**Handler class**: `com.alexthesis.validation.handler.ValidationHandler`

**Input**: `com.amazonaws.services.lambda.runtime.events.SQSEvent`

**Output**: `Void` (return value is ignored; Lambda measures success by absence of exception)

**Event source**: SQS queue `thesis-ingress-events`

**Behavior**:
- Processes each SQS record independently
- Routes decisions to appropriate queues
- Non-throwing exit on security rejection
- Throws exception on infrastructure failure (triggers SQS retry)

---

## Queue Message Formats

### Accepted Queue: `thesis-accepted-events`

Messages are serialized `SignedEvent` objects:

```json
{
  "content": {
    "eventId": "event-123",
    "timestampEpochMs": 1716238800000,
    "algorithm": "HMAC_SHA256",
    "keyId": "key1",
    "payload": { ... }
  },
  "signatureB64": "aGVsbG8gd29ybGQ="
}
```

### Rejected Queue: `thesis-rejected-events`

Messages are serialized `RejectedEvent` objects:

```json
{
  "originalEvent": { ... SignedEvent or null ... },
  "reason": "INVALID_SIGNATURE",
  "message": "Signature verification failed",
  "rejectedAtEpochMs": 1716238801000
}
```

---

## Sequence: Producer → Ingress → Validation → Accepted/Rejected

```
┌─────────────┐
│   Benchmark │
│    Client   │
└──────┬──────┘
       │ invoke with SignedEvent (to be signed)
       v
┌──────────────────────┐
│ Producer Lambda      │   (producer-lambda)
│ - Load key (SM)      │
│ - Sign event         │
│ - Publish to ingress │
└──────┬───────────────┘
       │ SignedEvent (ready-to-validate)
       v
    ┌─────────────────────┐
    │ SQS Queue           │
    │ thesis-ingress-     │
    │ events              │
    │ [batch size: 1]     │  (TODO: wiring via event source mapping)
    └──────┬──────────────┘
           │
    ╔══════════════════════════════════════════════════════════════╗
    ║   validation-lambda (THIS STORY)                            ║
    ║ ┌──────────────────────────────────────────────────────────┐║
    ║ │ ValidationHandler (entry point)                          ││
    ║ │ - Receives SQSEvent                                      ││
    ║ │ - Iterates records                                       ││
    ║ │ - Delegates to ValidationService                         ││
    ║ └──────────────────────────────────────────────────────────┘║
    ║ ┌──────────────────────────────────────────────────────────┐║
    ║ │ ValidationService (orchestration)                        ││
    ║ │ 1. Deserialize SignedEvent                              ││
    ║ │ 2. Validate structure                                    ││
    ║ │ 3. Load key from Secrets Manager                        ││
    ║ │ 4. Verify signature                                      ││
    ║ │ 5. Check replay window (configurable)                    ││
    ║ │ 6. Check dedup (placeholder with TODO)                   ││
    ║ │ 7. Route to accepted or rejected queue                   ││
    ║ └──────────────────────────────────────────────────────────┘║
    ║ ┌──────────────────────────────────────────────────────────┐║
    ║ │ ValidationRouter (decision routing)                      ││
    ║ │ - Publishes to thesis-accepted-events or                ││
    ║ │ - Publishes to thesis-rejected-events                    ││
    ║ └──────────────────────────────────────────────────────────┘║
    ╚══════════════════════════════════════════════════════════════╝
           │ \
           │  \
    Valid  │   \ Invalid
    ✓      │    ✗
           │     \
           v      v
    ┌─────────────┐   ┌─────────────────────┐
    │ SQS Queue   │   │ SQS Queue           │
    │ thesis-     │   │ thesis-rejected-    │
    │ accepted-   │   │ events              │
    │ events      │   │                     │
    └──────┬──────┘   └──────┬──────────────┘
           │                  │
           │ (Story 6)        │ (Story 7)
           v                  v
    ┌──────────────────┐   ┌──────────────────┐
    │ Persistence      │   │ Audit Lambda     │
    │ Lambda (TODO)    │   │ (TODO)           │
    │                  │   │                  │
    │ Write to         │   │ Write to         │
    │ thesis-ledger    │   │ thesis-audit     │
    └──────────────────┘   └──────────────────┘
```

---

## Dependencies and Secrets

### AWS Secrets Manager

The validation-lambda loads cryptographic keys from Secrets Manager using the `keyId` specified in each SignedEvent.

Expected secret format (JSON):

```json
{
  "keyId": "key1",
  "algorithm": "HMAC_SHA256",
  "keyMaterial": "base64-encoded-key-bytes"
}
```

Example secret names:
- `thesis/hmac/current`
- `thesis/rsa/current`
- `thesis/ecdsa/current`

(Producer and validation should use the same secret names.)

### DynamoDB Tables

#### thesis_dedup (Deduplication)

Currently a placeholder. Future implementation should:
- **Key**: `eventId` (partition key)
- **TTL attribute**: automatic expiry based on `thesis.dynamodb.dedup-ttl-seconds`
- **Usage**: Transactional write to prevent duplicate processing

#### thesis-ledger (Persistence)

**NOT** written by validation-lambda. Written by Persistence Lambda (Story 6).

#### thesis-audit (Auditing)

**NOT** written by validation-lambda. Written by Audit Lambda (Story 7).

---

## Known TODOs / Placeholders

1. **DedupStore.isNewEvent()** (checks/DedupStore.java)
   ```java
   // TODO: Implement DynamoDB dedup check
   // - Query thesis_dedup table for eventId
   // - If found, return false (duplicate)
   // - If not found, write new dedup entry with TTL and return true (new)
   // - Handle transactional writes with ledger table in the final version
   ```

2. **Event Source Mapping** (infrastructure)
   - Validation Lambda needs to be triggered by `thesis-ingress-events` SQS queue
   - Batch size: 1
   - Must enable ReportBatchItemFailures
   - This is part of infrastructure setup, not application code

---

## Contract with Producer Lambda

The validation-lambda expects events published to `thesis-ingress-events` by the producer-lambda to follow this contract:

1. **Queue name**: `thesis-ingress-events` (from producer config)
2. **Event format**: `SignedEvent` (serialized JSON)
3. **Signature boundary**: `SignedContent` (everything except `signatureB64`)
4. **Algorithms supported**:
   - `HMAC_SHA256` (symmetric)
   - `RSA_PSS_SHA256` (asymmetric)
   - `ECDSA_P256_SHA256` (asymmetric)
5. **Key reference**: `content.keyId()` used directly as-is to load from Secrets Manager
6. **Canonical serialization**: Uses `CryptoUtils.canonicalise()` for deterministic byte sequences

---

## Next Steps to Integrate

### Story 6 (Pending)
- [ ] Create Persistence Lambda
- [ ] Consume from `thesis-accepted-events`
- [ ] Write validated events to `thesis-ledger` DynamoDB table
- [ ] Return processing completion signal to benchmark

### Story 7 (Pending)
- [ ] Create Audit Lambda
- [ ] Consume from `thesis-rejected-events`
- [ ] Write rejection records to `thesis-audit` DynamoDB table
- [ ] Include rejection reason and metadata

### Validation-Lambda Enhancements (Story 8+)
- [ ] Implement full DedupStore with DynamoDB integration
- [ ] Add policy engine for dynamic algorithm and key validation
- [ ] Add support for key rotation (current + previous key verification)
- [ ] Add support for policy-driven reject reasons (e.g., POLICY_REJECTED, ALGORITHM_MISMATCH)

### Infrastructure (Story 4 continuation)
- [ ] Create event source mapping: `thesis-ingress-events` → `thesis-validation` Lambda
- [ ] Update LocalStack bootstrap to create mapping
- [ ] Set batch size to 1
- [ ] Enable ReportBatchItemFailures

---

## Testing and Validation

### Manual Smoke Test (after infrastructure wiring)

1. Start LocalStack:
   ```bash
   docker-compose up -d
   python3 localstack/bootstrap.py
   ```

2. Prepare a signed event (use producer-lambda or manually)

3. Publish to `thesis-ingress-events` via AWS CLI or SendMessage API

4. Observe validation-lambda receives and processes

5. Verify message appears in `thesis-accepted-events` or `thesis-rejected-events`

### Unit Tests

All ValidationServiceTest tests pass:
```bash
mvn -pl validation-lambda test
```

### Integration Tests (Future)

- End-to-end with LocalStack
- Verify signature verification matches producer
- Verify routing to correct queues
- Verify error handling paths

---

## Summary

Story 5 (Validation Lambda implementation) is **COMPLETE**.

The module is ready for:
1. Infrastructure wiring (event source mapping)
2. Integration with Persistence and Audit lambdas
3. End-to-end testing

The implementation follows the thesis architecture and provides the core security enforcement layer for the serverless event-processing platform.


