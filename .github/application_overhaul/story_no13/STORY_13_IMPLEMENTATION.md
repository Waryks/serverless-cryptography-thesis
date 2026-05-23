# Story 13 Implementation — Performance Instrumentation and Timing Collection

What I implemented for Story 13: a compact, JVM-local timing subsystem in the `commons` module and basic instrumentation in all four Lambdas (producer, validation, persistence, audit). The implementation focuses on accurate nanosecond timing (stored and exported as milliseconds), cold-start detection, and lightweight export via structured JSON logs. This provides the benchmark runner with internal timing visibility.

Summary of new files
- `commons/src/main/java/com/alexthesis/metrics/TimingStage.java` — enum of named timing stages used across lambdas.
- `commons/src/main/java/com/alexthesis/metrics/TimingSnapshot.java` — immutable snapshot of per-invocation timings; includes `toJson()`.
- `commons/src/main/java/com/alexthesis/metrics/TimingCollector.java` — in-memory collector that records start/stop times per eventId.
- `commons/src/main/java/com/alexthesis/metrics/MetricsContext.java` — convenient per-invocation handle (AutoCloseable) to start/stop stages and produce snapshots.
- `commons/src/main/java/com/alexthesis/metrics/MetricsRecorder.java` — small interface for pluggable exporters (not yet wired to implementations).
- `commons/src/main/java/com/alexthesis/metrics/ColdStartTracker.java` — per-JVM cold-start detection.

Where I instrumented the lambdas
- `producer-lambda/src/main/java/com/alexthesis/lambda/ProducerService.java`
  - Uses `MetricsContext` and `ColdStartTracker`.
  - Instruments KEY_LOADING, CONTENT_SERIALIZATION, SIGNING, SQS_PUBLISH, LAMBDA_HANDLER.
  - Emits a single-line JSON timing snapshot to stdout after publish.

- `validation-lambda/src/main/java/com/alexthesis/validation/service/ValidationService.java`
  - Creates `MetricsContext` per deserialized event and instruments POLICY_LOADING, KEY_LOADING, SIGNATURE_VERIFICATION, REPLAY_CHECK, DEDUP_CHECK, LAMBDA_HANDLER.
  - Emits a single-line JSON timing snapshot to stdout when a decision is reached.

- `persistence-lambda/src/main/java/com/alexthesis/persistence/service/PersistenceService.java`
  - Instruments LEDGER_MAPPING, LEDGER_WRITE, LAMBDA_HANDLER and emits timing snapshot.

- `audit-lambda/src/main/java/com/alexthesis/audit/service/AuditService.java`
  - Instruments AUDIT_MAPPING, AUDIT_WRITE, LAMBDA_HANDLER and emits timing snapshot.

Export and consumption
- Timing snapshots are emitted as compact JSON via `TimingSnapshot.toJson()` to standard output (one line). Example JSON:

  {"eventId":"abc-123","service":"validation","coldStart":false,"durations":{"SIGNATURE_VERIFICATION":3.2,"REPLAY_CHECK":1.1},"startMs":165...,"endMs":165...}

- Rationale: emitting structured timing JSON to logs is a low-friction way for the benchmark runner to collect internal timings. Optionally, the router/publishers can be extended to attach timing JSON as SQS message attributes (not yet implemented to avoid API churn in this iteration).

Notes and next steps
- The `commons` instrumentation is thread-safe and JVM-local. `ColdStartTracker` is keyed by service name and reports the first invocation as cold.
- The snapshot JSON uses Jackson (commons already declares jackson-databind) and is intentionally compact.
- Recommended follow-ups:
  - Attach timing JSON to outgoing SQS messages (message attribute `x-timings`) for end-to-end collection by the benchmark runner.
  - Add unit tests for `TimingCollector`, `MetricsContext`, and `ColdStartTracker` (not added in this change).
  - Provide a `MetricsRecorder` implementation that logs via the project logger instead of stdout, or publishes metrics to a dedicated metrics queue/topic if desired.

How to use
- Instrument code paths by creating a `MetricsContext` early in a Lambda handler:

  try (MetricsContext ctx = MetricsContext.create("validation", eventId, ColdStartTracker.isColdStartAndMark("validation"))) {
      ctx.start(TimingStage.SIGNATURE_VERIFICATION);
      // ... work ...
      ctx.stop(TimingStage.SIGNATURE_VERIFICATION);
      ctx.snapshot().ifPresent(s -> System.out.println(s.toJson()));
  }

Acceptance criteria mapping
- Timing subsystem exists: implemented under `commons`.
- Named timing stages exist: see `TimingStage` enum.
- All Lambdas collect timings: producer, validation, persistence, audit instrumented and emit snapshots.
- Cold start tracking exists: `ColdStartTracker` implemented and used.
- Benchmark can consume timing data: snapshots are emitted to logs as JSON (benchmark runner can parse logs); attaching to SQS attributes is left as an easy next step.
- Nanosecond precision internally: system uses System.nanoTime() and converts to milliseconds for export.

If you'd like, I can next:
- Add message-attribute propagation so snapshots are attached to SQS messages (changes to router and publisher APIs), or
- Implement a `MetricsRecorder` that logs via the project logger and replace System.out.println uses, or
- Add unit tests for the commons metrics classes and run the module tests.

