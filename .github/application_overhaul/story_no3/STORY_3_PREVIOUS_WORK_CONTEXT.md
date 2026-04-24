# Story 3 — Previous Work Context

## Purpose

This note captures what Story 2 completed so Story 3 can continue from the same shared contract.

---

## What was completed in Story 2

Story 2 delivered the shared core event model in the `commons` module (`com.alexthesis.messaging`).

Implemented files:

- `commons/src/main/java/com/alexthesis/messaging/Algorithm.java`
- `commons/src/main/java/com/alexthesis/messaging/SignedContent.java`
- `commons/src/main/java/com/alexthesis/messaging/SignedEvent.java`
- `commons/src/main/java/com/alexthesis/messaging/RejectedEvent.java`
- `commons/src/main/java/com/alexthesis/messaging/AuditReason.java`

Model details now in code:

- `Algorithm` enum values:
  - `HMAC_SHA256`
  - `RSA_PSS_SHA256`
  - `ECDSA_P256_SHA256`
- `SignedContent` record fields:
  - `String eventId`
  - `long timestampEpochMs`
  - `Algorithm algorithm`
  - `String keyId`
  - `JsonNode payload`
- `SignedEvent` record fields:
  - `SignedContent content`
  - `String signatureB64`
- `RejectedEvent` record fields:
  - `SignedEvent originalEvent`
  - `AuditReason reason`
  - `String message`
  - `long rejectedAtEpochMs`
- `AuditReason` enum values:
  - `INVALID_SIGNATURE`
  - `EXPIRED`
  - `REPLAY_DETECTED`
  - `UNKNOWN_KEY`
  - `ALGORITHM_MISMATCH`
  - `POLICY_REJECTED`
  - `DESERIALIZATION_ERROR`
  - `INTERNAL_ERROR`

---

## Acceptance status from Story 2

- Required classes and enums exist in `commons`.
- Records are used for event data classes.
- `SignedContent.payload` uses `JsonNode` as specified.
- `commons` compilation and tests were run successfully with:
  - `mvn -pl commons -am test -DskipITs`

---

## Canonical contract Story 3 should inherit

The following contract is now the baseline and should be treated as stable unless a deliberate migration is planned across all modules:

- Event transport shape is `SignedEvent(content, signatureB64)`.
- Signature boundary is `SignedContent` only.
- `signatureB64` is not part of the signed bytes.
- Enum names and record field names should remain unchanged for compatibility.

---

## Notes for the next story

- Keep using module name `commons` (repo convention), even though some docs mention `common`.
- Do not rename fields/enums in messaging records without coordinated updates in producer, consumer, and benchmark paths.
- Use this model as the shared JSON contract for SQS payloads, validation, audit routing, and persistence integration.

