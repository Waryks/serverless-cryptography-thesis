# Story 10 — Audit Lambda implementation notes

What I implemented:

- Added a new Maven module `audit-lambda` and registered it in the root `pom.xml`.
- Implemented the following packages and classes under `audit-lambda/src/main/java`:
  - `com.alexthesis.audit.handler.AuditHandler` — Lambda entry point (SQS -> service).
  - `com.alexthesis.audit.service.AuditService` — deserializes `RejectedEvent`, maps and persists.
  - `com.alexthesis.audit.mapping.AuditMapper` — converts `RejectedEvent` -> `AuditRecord` and generates `auditId`.
  - `com.alexthesis.audit.model.AuditRecord` — persistence model for DynamoDB.
  - `com.alexthesis.audit.repository.AuditRepository` — persists `AuditRecord` into DynamoDB table configured by `thesis.dynamodb.audit-table`.

Design notes and behavior:

- The handler is an SQS-triggered Lambda that receives `SQSEvent` batches and delegates each message body to `AuditService`.
- `AuditService` deserializes the incoming JSON as `RejectedEvent` (from `commons`) using Jackson. On deserialization errors it throws a RuntimeException so the SQS mapping can retry (infrastructure failure behavior).
- `AuditMapper` extracts available fields from the `RejectedEvent` and its nested `SignedEvent` safely (supports nulls). It generates a UUID `auditId` and records `persistedAtEpochMs`.
- `AuditRepository` writes items to DynamoDB using the AWS SDK v2 `DynamoDbClient` and the configured table name `thesis.dynamodb.audit-table`. The put includes `auditId` as primary key along with available fields.
- Logging follows existing project patterns (info logs on persistence and debug logs on batch processing).

Configuration:

- Add the following property in your runtime config (application.properties) or local overrides:

```
thesis.dynamodb.audit-table=thesis_audit
```

Smoke test suggestion:

1. Push an invalid event through the ingress/validation flow so a `RejectedEvent` is published to the `thesis-rejected-events` queue.
2. Ensure the `audit-lambda` SQS event source mapping is attached to `thesis-rejected-events` (batch size 1 recommended).
3. Run the local stack (LocalStack) or integration environment that provides SQS and DynamoDB endpoints.
4. Confirm that `thesis_audit` table gets an item with `auditId`, `eventId`, `reason`, `rejectedAtEpochMs` and `persistedAtEpochMs`.

Next steps / possible improvements:

- Add unit tests for `AuditMapper` and `AuditService`.
- Add smoke/integration tests similar to other modules.
- Consider adding an index or TTL attributes to the audit table for lifecycle management (out of scope for story).

