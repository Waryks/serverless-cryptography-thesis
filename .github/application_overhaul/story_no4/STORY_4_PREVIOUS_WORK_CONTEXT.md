# Story 4 - Previous Work Context

## Purpose

This note captures what Story 3 delivered so Story 4 can continue from the same migration contract.

---

## What was completed in Story 3

Story 3 implemented and aligned the `producer-lambda` path with the migration documents.

Implemented/updated behavior:

- Lambda entrypoint delegates to producer orchestration:
  - `producer-lambda/src/main/java/com/alexthesis/lambda/ProducerHandler.java`
  - `producer-lambda/src/main/java/com/alexthesis/lambda/ProducerService.java`
- Signing flow implemented for all required algorithms:
  - `HMAC_SHA256`
  - `RSA_PSS_SHA256`
  - `ECDSA_P256_SHA256`
- Key loading from Secrets Manager is performed using `SignedContent.keyId` directly.
- Signed event is published to SQS via:
  - `producer-lambda/src/main/java/com/alexthesis/events/QueuePublisher.java`
- Producer response contract is returned with:
  - `eventId`
  - `coldStart`
  - `durationMs`

---

## Contract decisions now in code

### Queue contract

- Producer queue config is now set to `thesis-ingress-events` in:
  - `producer-lambda/src/main/resources/application.properties`
  - `producer-lambda/src/test/resources/application.properties`
- `thesis.sqs.queue-name` is treated as a queue name (not a raw URL).
- `QueuePublisher` resolves queue URL via `GetQueueUrl` and then sends messages with that resolved URL.

### Key lookup contract

- Producer signing key lookup uses `content.keyId()` as-is for all algorithms.
- Producer no longer appends `/private` during key resolution.

### Event contract continuity

- Shared transport shape remains `SignedEvent(content, signatureB64)` from `commons`.
- Signature boundary remains `SignedContent` (not `signatureB64`).

---

## Validation and test status

Producer tests were executed after alignment changes.

Command used:

```zsh
cd "/Users/sasha/Dev/repos/serverless-cryptography-thesis"
mvn -pl producer-lambda -am test -DskipITs
```

Observed result:

- Build status: `SUCCESS`
- Test totals: `25` run, `0` failures, `0` errors, `0` skipped

Additional focused check:

```zsh
cd "/Users/sasha/Dev/repos/serverless-cryptography-thesis"
mvn -pl producer-lambda -Dtest=ProducerComponentTest test -DskipITs
```

Observed result:

- Build status: `SUCCESS`
- Component tests: `3` run, `0` failures
- Producer publish path executed for HMAC/RSA/ECDSA and produced signed SQS message payloads in test flow.

---

## Notes for Story 4

- Treat producer contracts above as the current migration baseline unless a coordinated cross-module migration is planned.
- If Story 4 depends on queue names, use `thesis-ingress-events` for producer ingress.
- Other modules and docs may still reference legacy `thesis-events`; update carefully to avoid partial-contract drift.
- Keep enum names and record field names in `commons` unchanged for compatibility with benchmark and downstream consumers.

