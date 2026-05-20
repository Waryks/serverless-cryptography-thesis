# Story 7 — Implement Key Management and Rotation Subsystem

## Goal

Implement a dedicated key management subsystem responsible for loading, parsing, validating, caching, and rotating cryptographic keys used by the platform.

This subsystem should support:

- current keys
- previous keys
- multiple algorithms
- Secrets Manager integration
- optional key caching
- rotation-aware verification

The subsystem must be shared across signing and verification operations.

---

## Why this story matters

Cryptographic operations are not only affected by the signing algorithm itself.

In serverless systems, key handling introduces major overhead through:

- Secrets Manager access
- network calls
- key parsing
- PEM decoding
- object creation
- cache initialization

This subsystem is important because the thesis is not only measuring raw cryptographic performance, but also the operational overhead of secure event processing in serverless environments.

The subsystem also introduces realistic security lifecycle behavior such as key rotation.

---

## Architecture context

Before this story:

```text
Producer Lambda
   |
   └── directly loads single key
```

```text
Validation Lambda
   |
   └── directly loads verification key
```

After this story:

```text
Producer Lambda
   |
   v
Key Management Subsystem
```

```text
Validation Lambda
   |
   v
Key Management Subsystem
   |
   ├── current key
   ├── previous key
   ├── cache
   ├── parser
   └── rotation logic
```

---

## High-level concept

Instead of Lambdas directly handling raw Secrets Manager responses, all key operations should go through a centralized subsystem.

The subsystem should become responsible for:

- retrieving secrets
- parsing key material
- validating algorithm compatibility
- resolving current/previous keys
- optionally caching parsed keys

This separates trust management from business logic.

---

## Module location

The subsystem should initially live in:

```text
common/
```

Recommended package structure:

```text
common/
└── src/main/java/com/alexthesis/security/keys/
    ├── KeyDescriptor.java
    ├── KeyProvider.java
    ├── KeyResolver.java
    ├── KeyCache.java
    ├── KeyParser.java
    ├── RotationPolicy.java
    ├── ParsedKey.java
    └── KeyValidationResult.java
```

The implementation may later be split into a dedicated module if needed.

---

## Key naming convention

Secrets Manager keys should follow this naming structure:

```text
thesis/<algorithm>/<stage>
```

Examples:

```text
thesis/hmac/current
thesis/hmac/previous

thesis/rsa/current
thesis/rsa/previous

thesis/ecdsa/current
thesis/ecdsa/previous
```

This structure keeps key resolution predictable.

---

## Secret structure

Secrets should contain structured JSON.

Example:

```json
{
  "keyId": "rsa-2026-01",
  "algorithm": "RSA_PSS_SHA256",
  "keyMaterial": "-----BEGIN PRIVATE KEY----- ..."
}
```

The subsystem should parse this structure instead of treating secrets as raw strings.

---

## KeyDescriptor

The system needs a metadata model describing a key.

Suggested fields:

```text
keyId
algorithm
stage
loadedAtEpochMs
source
```

Purpose:

- identify key metadata
- support rotation
- support audit logging
- support benchmark instrumentation

---

## ParsedKey

The system should separate:

```text
raw key material
```

from:

```text
parsed crypto objects
```

Examples:

- SecretKey
- PrivateKey
- PublicKey

This prevents repeated parsing during warm invocations if caching is enabled.

---

## KeyProvider

Responsibilities:

- connect to Secrets Manager
- retrieve secret values
- deserialize secret JSON
- return key descriptors or raw key objects

The provider should not contain cryptographic verification logic.

---

## KeyResolver

Responsibilities:

- resolve current key
- resolve previous key
- select keys based on algorithm
- support policy-driven rotation behavior

Examples:

```text
resolveCurrent(HMAC)
resolvePrevious(RSA)
```

---

## RotationPolicy

The system needs a rotation-aware verification strategy.

Example:

```text
1. Try current key
2. If verification fails:
   - check whether policy allows previous key
3. Try previous key
4. If previous succeeds:
   - accept during grace period
5. Otherwise reject
```

This models realistic key rotation behavior.

---

## KeyCache

The subsystem should support optional caching.

Possible cache modes:

### Disabled

Every invocation:

```text
Secrets Manager call
parse key
use key
```

Useful for worst-case measurements.

---

### Enabled

Warm invocations may reuse parsed keys.

Useful for realistic warm performance measurements.

---

## Cache behavior

Suggested configuration:

```text
thesis.security.key-cache-enabled=true
thesis.security.key-cache-ttl-ms=300000
```

The cache should support:

- cache hit
- cache miss
- expiration
- invalidation

The first implementation may use simple in-memory maps.

---

## Why caching matters for the thesis

Caching is one of the most important variables affecting warm invocation latency.

The benchmark should later compare:

```text
cached keys
vs
uncached keys
```

This allows the thesis to measure:

- Secrets Manager overhead
- key parsing overhead
- warm reuse effects

---

## Algorithm compatibility

The subsystem should validate compatibility between:

```text
algorithm enum
```

and:

```text
key material type
```

Examples:

```text
RSA key + HMAC algorithm
→ invalid
```

```text
ECDSA key + RSA verification
→ invalid
```

This prevents incorrect key usage.

---

## Producer integration

The Producer Lambda should use the subsystem to:

1. resolve current signing key
2. parse key material
3. sign content

The Producer should no longer directly load raw secrets.

---

## Validation integration

The Validation Lambda should use the subsystem to:

1. resolve verification keys
2. optionally resolve previous keys
3. perform rotation-aware verification

The Validation Lambda should no longer directly access Secrets Manager.

---

## Benchmark impact

The benchmark should later support scenarios such as:

### Current key only

Measure baseline verification.

---

### Current + previous key verification

Measure additional verification overhead.

---

### Cache disabled

Measure maximum Secrets Manager + parsing overhead.

---

### Cache enabled

Measure warm-path optimization effects.

---

### Rotation stress test

Simulate:

```text
frequent key changes
```

and measure:

- cache invalidation overhead
- additional lookup cost
- verification retry cost

---

## Smoke test expectations

A smoke test should be able to:

1. Resolve current HMAC key
2. Resolve previous RSA key
3. Parse key material successfully
4. Detect incompatible algorithm/key combinations
5. Use cache if enabled

At this stage, smoke tests may use placeholder keys.

---

## Acceptance criteria

This story is complete when:

1. Key subsystem exists.
2. Secrets are loaded through the subsystem.
3. Current keys can be resolved.
4. Previous keys can be resolved.
5. Structured secret JSON is supported.
6. Parsed key objects are supported.
7. Optional cache exists.
8. Rotation-aware resolution exists.
9. Producer uses the subsystem.
10. Validation Lambda uses the subsystem.
11. Algorithm/key compatibility checks exist.

---

## Out of scope

Do not implement yet:

- distributed cache
- automatic key rotation jobs
- external KMS integration
- asymmetric public/private split management
- cross-region replication
- advanced trust chain validation

This story focuses on realistic serverless key lifecycle management.
