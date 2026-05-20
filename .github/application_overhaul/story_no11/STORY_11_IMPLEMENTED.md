# Story 11 — Deduplication and Replay Protection implementation notes

What I implemented:

- Completed the validation-stage replay/dedup security flow in `validation-lambda`.
- Replaced the placeholder deduplication logic with a DynamoDB-backed conditional write in `com.alexthesis.validation.checks.DedupStore`.
- Added `com.alexthesis.validation.checks.ProcessedEventRecord` as the persistence model used to store processed events in the dedup table.
- Kept replay checking in `com.alexthesis.validation.checks.ReplayChecker` and integrated both checks through `ValidationService`.
- Preserved the existing policy-driven behavior in `ValidationService` so replay and dedup can be enabled or disabled per policy.
- Added focused unit tests for the dedup store in `validation-lambda/src/test/java/com/alexthesis/validation/checks/DedupStoreTest.java`.

Behavior:

- Replay protection uses the configured window from `thesis.security.replay-window-ms`.
- Deduplication writes each processed `eventId` into `thesis_dedup` using a conditional `PutItem` with `attribute_not_exists(eventId)`.
- Duplicate events return `false` from `DedupStore.isNewEvent(...)`, which causes `ValidationService` to route the event to the rejected queue with `AuditReason.REPLAY_DETECTED`.
- Events outside the replay window are rejected with `AuditReason.EXPIRED`.
- Infrastructure failures from DynamoDB are not swallowed; they propagate so the Lambda/SQS flow can retry.
- Stored dedup records include:
  - `eventId`
  - `processedAtEpochMs`
  - `algorithm`
  - `keyId`
  - `ttl`

Configuration used:

```properties
thesis.security.replay-check-enabled=true
thesis.security.replay-window-ms=300000
thesis.security.dedup-enabled=true
thesis.dynamodb.dedup-table=thesis-dedup
thesis.dynamodb.dedup-ttl-seconds=86400
```

Validation performed:

- Ran the module build and tests with the reactor:

```bash
mvn -pl validation-lambda -am test -DskipITs
```

- Result: build succeeded and the validation-lambda test suite passed.

Notes:

- The validation service already had the policy integration and rejected-routing behavior in place.
- This story primarily completed the missing DynamoDB-backed dedup store and added coverage for the new behavior.

