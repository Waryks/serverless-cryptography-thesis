# Story 6 — Policy Engine Implementation Summary

## Completion Status

✅ **Story 6 is IMPLEMENTED and BUILDABLE**

This document summarizes the policy-engine work completed inside `validation-lambda` and explains the main design choices so the next agent can continue from here.

---

## What Was Implemented

### 1. New policy package in `validation-lambda`

Created a dedicated policy subsystem under:

```text
validation-lambda/src/main/java/com/alexthesis/validation/policy/
```

Added these classes:

- `SecurityPolicy`
- `PolicyLoader`
- `PolicyResolver`
- `PolicyValidationResult`
- `PolicyEngine`

This keeps the policy logic separate from the core validation orchestration and makes future evolution easier.

---

### 2. `SecurityPolicy` model

Implemented a compact immutable policy model with the following fields:

- `policyId`
- `allowedAlgorithm`
- `replayCheckEnabled`
- `replayWindowMs`
- `dedupEnabled`
- `allowPreviousKey`
- `strictValidation`

#### Reasoning

The story explicitly asked not to overengineer the first version. The model captures the required knobs without introducing a rule DSL, versioning, or dynamic persistence.

---

### 3. Config-backed policy loading

Implemented `PolicyLoader` to read policies from MicroProfile configuration using the prefix:

```text
thesis.policy.<policyId>.*
```

Implemented `PolicyResolver` to choose a policy for each event using algorithm-based mapping:

```text
thesis.policy.algorithm.<ALGORITHM>
```

with fallback to:

```text
thesis.policy.default
```

#### Reasoning

The story recommended either a single global policy or policy-by-algorithm. Algorithm-based resolution was chosen because it gives the benchmark more flexibility while still remaining simple and configuration-driven.

---

### 4. Policy evaluation result object

Added `PolicyValidationResult` to represent whether policy evaluation passed and, if not, why it failed.

It carries:

- policy reference
- allowed/rejected flag
- rejection reason
- rejection message

#### Reasoning

The validation service needs a clean way to react to policy decisions without mixing them with cryptographic verification or queue routing logic.

---

### 5. Policy engine

Implemented `PolicyEngine` to enforce the policy rules before validation proceeds.

Current responsibilities:

- resolve the policy for an event
- reject on algorithm mismatch
- reject on strict validation failures
- provide a helper for previous-key lookup

The engine does **not** perform cryptographic verification.

#### Reasoning

The story said the policy engine should decide validation behavior but should not do crypto itself. That separation was kept intentionally so the verifier remains the single place for signature validation.

---

### 6. Validation flow refactor

Refactored `ValidationService` so the flow is now:

1. Deserialize the message
2. Validate basic structure
3. Resolve policy
4. Apply policy decisions
5. Load key material
6. Verify signature
7. Apply policy-controlled replay check
8. Apply policy-controlled dedup check
9. Route accepted/rejected event

#### Key changes

- replay/dedup are now controlled by policy rather than only by fixed flags
- algorithm compatibility is now validated through the policy engine
- previous-key support is now policy-driven
- rejections are routed directly instead of relying on a custom security exception path

#### Reasoning

The main goal of the story was to move validation from a hardcoded pipeline to a configurable policy-driven architecture. This refactor keeps the validation layer slimmer and makes the system more extensible for future experiments.

---

### 7. Replay checker update

Extended `ReplayChecker` with an overload that accepts a replay window from the policy:

```text
isWithinReplayWindow(content, windowMs)
```

The original config-based method still exists and delegates to the configured default value.

#### Reasoning

This preserves backward compatibility while allowing policies to define different replay windows per algorithm or policy profile.

---

### 8. Configuration added

Updated both main and test `application.properties` with policy configuration examples:

- `strict-rsa`
- `relaxed-hmac`
- `strict-ecdsa`

with algorithm mapping entries like:

```text
thesis.policy.algorithm.HMAC_SHA256=relaxed-hmac
thesis.policy.algorithm.RSA_PSS_SHA256=strict-rsa
thesis.policy.algorithm.ECDSA_P256_SHA256=strict-ecdsa
```

#### Reasoning

Keeping the policies in config satisfies the story requirement that policies can be changed without Java code changes.

---

## Test Coverage Added

### New tests

- `PolicyResolutionTest`
- `PolicyEngineTest`

### Updated tests

- `ValidationServiceTest`

#### What is covered

- algorithm-based policy resolution
- strict vs relaxed policy behavior
- algorithm mismatch rejection
- strict validation rejection
- replay and dedup toggles
- previous-key fallback acceptance path

---

## Validation Result

The module was verified with:

```bash
mvn -pl validation-lambda -am test
```

Result: **BUILD SUCCESS**

---

## Important Design Decisions

### 1. Algorithm-based policy resolution

Chosen over a single global policy because it provides better benchmarking flexibility without adding much complexity.

### 2. Static config-backed policy loading

Chosen because the story explicitly said to avoid DynamoDB/S3/Secrets Manager policy loading for now.

### 3. Policy engine separated from crypto

The engine decides whether validation should proceed; it does not perform signature verification.

### 4. Previous-key fallback is heuristic-based for now

Implemented a simple key-ID transformation helper in `PolicyEngine`:

- `.../current` → `.../previous`
- `...-current` → `...-previous`
- `...:current` → `...:previous`
- fallback: append `/previous`

This is intentionally lightweight and can be improved later if the project adopts a stricter key naming convention.

### 5. Rejections are routed directly

The old `SecurityRejectionException` path was removed from the validation service because the service now routes policy/security failures immediately.

---

## Current Limitations / Follow-Up Ideas

These are not blockers, but likely next steps:

1. **Dedup store is still a placeholder**
   - policy can disable/enable dedup
   - actual DynamoDB duplicate detection is still not implemented

2. **Previous-key lookup is heuristic-based**
   - if the project later standardizes key naming, this can become stricter

3. **Policy loader is config-backed only**
   - future stories may move policy definitions into DynamoDB, S3, or Secrets Manager

4. **Policy errors currently rely on configuration correctness**
   - invalid or missing policy config throws during startup/runtime resolution

---

## Handoff Notes for the Next Agent

If you continue from here, the most likely next improvements are:

- tighten policy resolution and validation rules
- decide whether policy metadata should live in `commons`
- implement real DynamoDB deduplication
- improve previous-key resolution if the naming convention becomes fixed
- add smoke-test coverage for policy mismatch and relaxed-policy acceptance scenarios

The current implementation already satisfies the story 6 acceptance criteria at a code level and is buildable.

