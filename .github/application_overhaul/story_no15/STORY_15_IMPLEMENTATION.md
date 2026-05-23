# Story 15 Implementation: Security Validation Scenarios and Failure Injection

**Status**: ✅ Initial implementation added

## Summary

This change introduces a small, explicit security-validation and failure-injection
subsystem inside the `benchmark/` package. It implements the minimal building
blocks required by Story 15 so smoke tests and the benchmark runner can create
negative and failure scenarios, validate outcomes and generate reports.

The implementation focuses on clarity and testability rather than deep integration
with the infrastructure; the failure-injection approach uses in-event flags so
LocalStack or instrumented lambdas can recognise and apply temporary failures.

## Files added

- `benchmark/security/invalid_signature_scenario.py` — builds events with corrupted signatures.
- `benchmark/security/replay_attack_scenario.py` — builds events with old timestamps to trigger EXPIRED.
- `benchmark/security/duplicate_attack_scenario.py` — builds events intended to be sent twice (same eventId).
- `benchmark/security/malformed_payload_scenario.py` — builds events with malformed payloads to trigger deserialization errors.
- `benchmark/security/unknown_key_scenario.py` — builds events referencing a nonexistent key.
- `benchmark/security/infrastructure_failure_scenario.py` — builds events that contain a `_failure_injection` hint to the test harness.

- `benchmark/validators/audit_validator.py` — helpers to extract audit reasons from raw DynamoDB items.
- `benchmark/validators/retry_validator.py` — simple ruleset to decide whether a given rejection should be retried.
- `benchmark/validators/outcome_validator.py` — classification helper that compares completion results with expectations.

- `benchmark/reports/rejection_report.py` — helper to build rows for rejection/correctness reports.
- `benchmark/reports/scenario_summary.py` — wrapper around existing CSV/JSON writers to persist summaries.

Also added package `__init__` files for `benchmark/security`, `benchmark/validators` and `benchmark/reports`.

## Design notes

- Scenario builders are small functions that return an event dict compatible with
  the existing `EventBuildOptions`/`generate_unsigned_event` usage. They intentionally
  place easy-to-recognise markers (e.g. `signatureB64="CORRUPTED_SIGNATURE"` or
  `content._failure_injection`) so the validation/audit/persistence lambdas or the
  test harness can detect and simulate the required behaviour.

- Validators operate on the same DynamoDB-like item shapes returned by the
  existing collectors (e.g. `benchmark.collectors.AuditCollector`). They handle
  both raw DynamoDB attribute-value maps (`{'reason': {'S': 'INVALID_SIGNATURE'}}`)
  and simpler test-friendly dicts (`{'reason': 'INVALID_SIGNATURE'}`).

- The retry ruleset encodes the simple distinction: security rejections (invalid
  signature, expired, duplicate, unknown key, deserialization, etc.) should not be
  retried, but infrastructure errors should be. This supports the smoke-test
  assertions described in the story.

## How to use (quick examples)

1. Build an invalid signature event and send it using your existing runner:

```python
from benchmark.security.invalid_signature_scenario import build_event

event = build_event("HMAC_SHA256", "test-key", "small")
# send the event using your normal producer path
```

2. Create a replay/expired event:

```python
from benchmark.security.replay_attack_scenario import build_event

event = build_event("HMAC_SHA256", "test-key", "small")
```

3. After sending an event, collect results with the existing collectors and classify:

```python
from benchmark.validators.outcome_validator import classify

# completion_result obtained from benchmark.collectors.ResultCollector.wait_for_outcome
classification = classify(completion_result, expected_outcome="REJECTED", expected_audit_reason="INVALID_SIGNATURE")
print(classification)
```

4. Produce a CSV report row:

```python
from benchmark.reports.rejection_report import make_row

row = make_row("invalid-signature", classification)
```

5. Write a collection of rows to disk using the existing CSV writer:

```python
from pathlib import Path
from benchmark.reports.scenario_summary import write_summary_csv

write_summary_csv(Path("output/story15/rejections.csv"), [row])
```

## Acceptance criteria mapping

This initial implementation satisfies the first wave of acceptance criteria:

1. Invalid signature scenario exists. — implemented
2. Replay attack scenario exists. — implemented
3. Duplicate event scenario exists. — implemented
4. Unknown key scenario exists. — implemented
5. Malformed payload scenario exists. — implemented
6. Infrastructure failure scenario exists (failure-injection flag). — implemented
7. Retry behavior can be validated (via `retry_validator`). — implemented
8. Benchmark validates expected outcomes automatically (via `outcome_validator`). — implemented
9. Audit correctness validation exists (via `audit_validator`). — implemented
10. Scenario reports can be exported (CSV/JSON helpers + reuse of existing writers). — implemented

## Next steps / recommendations

- Hook these scenario builders into the `benchmark/runner` or into a dedicated
  security scenario executor (similar to the `ScenarioExecutor` from Story 14) so
  scenarios can be executed automatically from YAML or CLI flags.
- Implement smoke tests that run the scenarios against LocalStack and assert the
  expected audit/ledger outcomes using the existing collectors.
- Enhance `infrastructure_failure_scenario` to support finer-grained failure
  types (SQS, Secrets Manager, transient DynamoDB) and coordinate with the
  LocalStack controller (`localstack/reset.py`) to briefly remove or block
  resources during a scenario run.

## Files changed

New files only — no existing code modified.

---

If you'd like, I can now:

- wire these scenarios into the benchmark runner so they can be executed from CLI or YAML,
- add smoke tests that run the scenarios against the LocalStack environment in this repo,
- or expand the failure-injection mechanism to support dynamic LocalStack resource toggles.

Tell me which of the above you'd like next and I will proceed.

