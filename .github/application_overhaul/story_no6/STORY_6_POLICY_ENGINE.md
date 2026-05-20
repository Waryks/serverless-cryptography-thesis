# Story 6 — Implement Policy Engine

## Goal

Implement a policy-driven validation subsystem that controls how events are verified and processed inside the Validation Lambda.

The policy engine should allow the platform to dynamically apply different security rules without changing validation code.

This transforms the application from a fixed validation flow into a configurable secure event-processing platform.

---

## Why this story matters

Without a policy engine, the platform behaves as a hardcoded pipeline:

- always use the same algorithm
- always enforce replay checks
- always allow or deny key rotation
- always apply the same validation rules

That limits both:

- research flexibility
- architectural complexity

The policy engine allows the thesis to compare not only cryptographic algorithms, but also different security enforcement strategies.

This is one of the key architectural features that makes the system thesis-worthy.

---

## Architecture context

Before this story:

```text
Validation Lambda
   |
   ├── verify signature
   ├── replay check
   ├── dedup check
   └── route decision
```

After this story:

```text
Validation Lambda
   |
   v
Policy Engine
   |
   ├── allowed algorithm
   ├── replay enabled?
   ├── replay window size
   ├── dedup enabled?
   ├── allow previous key?
   ├── strict validation?
   └── routing behavior
```

---

## High-level concept

A policy defines how a specific event should be validated.

The Validation Lambda should no longer hardcode all checks directly.

Instead:

```text
event
   ↓
load policy
   ↓
apply policy-controlled validation
   ↓
accept or reject
```

---

## Module location

The policy subsystem should primarily live inside:

```text
validation-lambda/
```

Recommended package structure:

```text
validation-lambda/
└── src/main/java/com/alexthesis/validation/policy/
    ├── SecurityPolicy.java
    ├── PolicyLoader.java
    ├── PolicyResolver.java
    ├── PolicyValidationResult.java
    └── PolicyEngine.java
```

Some shared models may later move into:

```text
common/
```

if needed across modules.

---

## SecurityPolicy model

A policy represents validation rules.

Suggested fields:

```text
policyId
allowedAlgorithm
replayCheckEnabled
replayWindowMs
dedupEnabled
allowPreviousKey
strictValidation
```

Optional future fields:

```text
maxPayloadSize
allowedKeyIds
auditLevel
requiredMetadata
```

Do not overengineer the first implementation.

---

## Policy examples

### Strict RSA policy

```text
policyId = strict-rsa
algorithm = RSA_PSS_SHA256
replay enabled = true
replay window = 5 minutes
dedup enabled = true
allow previous key = false
strict validation = true
```

---

### Relaxed HMAC policy

```text
policyId = relaxed-hmac
algorithm = HMAC_SHA256
replay enabled = false
dedup enabled = false
allow previous key = true
strict validation = false
```

---

## Policy loading strategy

Initial implementation may use:

- application.properties
- YAML
- static in-memory configuration

Later versions may load from:

```text
DynamoDB
S3
Secrets Manager
```

For this story, simple local configuration is preferred.

---

## Policy resolution

The platform needs a way to determine which policy applies to an event.

Possible strategies:

### Option A — Single global policy

All events use one configured policy.

Simplest initial implementation.

---

### Option B — Policy by algorithm

```text
HMAC events → HMAC policy
RSA events → RSA policy
ECDSA events → ECDSA policy
```

---

### Option C — Policy ID inside payload

Future possibility:

```text
payload.policyId
```

For this story, Option A or B is recommended.

---

## Policy engine responsibilities

The policy engine should decide:

### Algorithm compatibility

Example:

```text
policy requires RSA
event uses HMAC
→ reject
```

---

### Replay enforcement

Example:

```text
policy replay enabled = true
event timestamp too old
→ reject
```

---

### Dedup enforcement

Example:

```text
policy dedup enabled = true
event already processed
→ reject
```

---

### Previous key support

Example:

```text
policy allows previous key
current key verification fails
previous key verification succeeds
→ accept
```

---

### Strict validation behavior

Example:

Strict mode:

```text
missing metadata → reject
```

Relaxed mode:

```text
missing metadata → warning only
```

---

## Integration with Validation Lambda

The Validation Lambda should delegate decisions to the policy engine.

Instead of:

```text
if replay enabled
if dedup enabled
if previous key allowed
```

inside validation code, the flow becomes:

```text
load policy
↓
policy decides validation behavior
↓
validator applies checks
```

This keeps the validation layer cleaner and more extensible.

---

## PolicyEngine responsibilities

Suggested responsibilities:

1. Load or resolve policy
2. Validate algorithm compatibility
3. Decide which checks are required
4. Expose validation decisions
5. Produce rejection reasons if policy fails

The engine should not directly perform cryptographic operations.

Crypto verification remains the responsibility of the verifier subsystem.

---

## Rejection scenarios

The policy engine may trigger rejections such as:

- POLICY_REJECTED
- ALGORITHM_MISMATCH
- UNKNOWN_KEY
- EXPIRED
- REPLAY_DETECTED

Use the shared `AuditReason` enum.

---

## Configuration examples

Possible configuration:

```text
thesis.policy.default=strict-rsa

thesis.policy.strict-rsa.algorithm=RSA_PSS_SHA256
thesis.policy.strict-rsa.replay-enabled=true
thesis.policy.strict-rsa.replay-window-ms=300000
thesis.policy.strict-rsa.dedup-enabled=true
thesis.policy.strict-rsa.allow-previous-key=false
```

---

## Benchmark impact

The policy engine enables benchmark scenarios such as:

### Compare replay enabled vs disabled

Measure:

- additional validation latency
- DynamoDB lookup overhead

---

### Compare strict vs relaxed validation

Measure:

- rejection rates
- validation complexity impact

---

### Compare previous-key enabled vs disabled

Measure:

- additional key lookup and verification overhead

This makes the benchmark much more valuable.

---

## Smoke test expectations

A smoke test should be able to:

1. Send an event using HMAC
2. Apply HMAC policy
3. Accept or reject based on policy rules

Examples:

```text
RSA policy + HMAC event
→ reject
```

```text
HMAC policy + HMAC event
→ accept
```

---

## Acceptance criteria

This story is complete when:

1. SecurityPolicy model exists.
2. Validation Lambda can load or resolve a policy.
3. Policy controls replay behavior.
4. Policy controls dedup behavior.
5. Policy controls algorithm compatibility.
6. Policy can enable/disable previous key support.
7. Validation logic no longer hardcodes all security behavior.
8. Rejections can occur due to policy rules.
9. Policies are configurable without changing Java code.

---

## Out of scope

Do not implement yet:

- dynamic policy loading from DynamoDB
- distributed policy management
- UI/dashboard for policies
- policy versioning
- advanced rule DSL

This story focuses on introducing configurable validation behavior into the platform.
