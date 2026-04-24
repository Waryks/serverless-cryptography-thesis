# Story 2 — Create Core Event Model

## Goal

Create the shared event model used by all Lambdas and the benchmark client.

This model defines the message contract that flows through SQS and is used for signing, verification, routing, audit, and persistence.

---

## Why this story matters

Every module must agree on the exact event structure.

The event model is central because it determines:

- what is sent through SQS
- what is cryptographically signed
- what is verified
- what is stored in DynamoDB
- what the benchmark generates

A stable model prevents mismatch between producer, validator, persistence, audit, and benchmark modules.

---

## Module location

This story belongs in:

common/

The common module should contain:

- Algorithm.java
- SignedEvent.java
- SignedContent.java
- RejectedEvent.java
- AuditReason.java

---

## Core event model

### SignedEvent

Represents the full message transported through SQS.

Fields:

- SignedContent content
- String signatureB64

---

### SignedContent

Represents the exact content that is signed.

Fields:

- String eventId
- long timestampEpochMs
- Algorithm algorithm
- String keyId
- JsonNode payload

Important:

Only SignedContent is signed. Signature field is not included in signing.

---

## Algorithm enum

Values:

- HMAC_SHA256
- RSA_PSS_SHA256
- ECDSA_P256_SHA256

---

## Payload

Payload should be JsonNode to allow flexible structure and benchmarking.

---

## RejectedEvent

Fields:

- SignedEvent originalEvent
- AuditReason reason
- String message
- long rejectedAtEpochMs

---

## AuditReason enum

Values:

- INVALID_SIGNATURE
- EXPIRED
- REPLAY_DETECTED
- UNKNOWN_KEY
- ALGORITHM_MISMATCH
- POLICY_REJECTED
- DESERIALIZATION_ERROR
- INTERNAL_ERROR

---

## Serialization

- Must be compatible with Jackson
- Prefer Java records
- Stable JSON structure required

---

## Signature boundary

Signed:

- SignedContent

Not signed:

- signatureB64
- transport metadata

---

## Acceptance criteria

- All classes exist in common module
- Project compiles
- Shared across all modules

---

## Out of scope

- crypto logic
- policy engine
- persistence
