# Story 14: Quick Reference Guide

## The Problem Story 14 Solves

**Before**: Changing experiments required modifying Python code
**After**: Experiments are defined in YAML, loaded and executed without code changes

## Quick Start (60 seconds)

### 1. Load Experiments
```python
from benchmark.models import ScenarioLoader

experiments = ScenarioLoader.load_from_file(
    "benchmark/config/experiment_config_story14.yaml"
)
```

### 2. Validate
```python
from benchmark.models import ScenarioValidator

errors = ScenarioValidator.validate_all(experiments)
if not errors:
    print("✓ All valid")
```

### 3. Create Custom Experiment
```python
from benchmark.models import *

exp = ExperimentDefinition(
    experiment_id="my_test",
    description="Custom test",
    scenario="accepted",
    crypto_config=CryptoConfig(algorithm=Algorithm.RSA_PSS_SHA256),
    workload_config=WorkloadConfig(payload_size=PayloadSize.LARGE),
    cold_start_config=ColdStartConfig(mode=ColdStartMode.PER_ITERATION),
    replay_dedup_config=ReplayDedupConfig(),
    iterations=10,
    expected_outcome=ExpectedOutcome.ACCEPTED,
)
```

### 4. Check Configuration
```python
print(exp.compute_fingerprint())  # Reproducible hash
print(exp.is_cold_start_scenario())  # Check cold start
print(exp.to_dict())  # Export configuration
```

### 5. Classify Results
```python
from benchmark.models import ResultValidator

results = [...]  # List of ScenarioExecutionResult
classified = ResultValidator.classify_batch(results, exp)
summary = ResultValidator.summarize(classified)

print(f"Success rate: {summary['success_rate']:.1%}")
```

## Configuration Options

### Algorithm Selection
```yaml
algorithm: HMAC_SHA256          # or RSA_PSS_SHA256, ECDSA_P256_SHA256
```

### Payload Size
```yaml
payload_size: small             # or medium, large
```

### Cold Start Behavior
```yaml
cold_start_mode: per_iteration  # or none, per_experiment, idle_wait
```

### Caching
```yaml
cache_enabled: true             # or false
```

### Key Rotation
```yaml
rotation_mode: current_and_previous  # or current_only
```

### Security
```yaml
replay_enabled: true            # Enable replay protection
dedup_enabled: true             # Enable deduplication
replay_window_ms: 300000        # 5 minutes
```

### Execution
```yaml
execution_mode: sequential      # or concurrent
```

### Scenario Type
```yaml
scenario: accepted              # or rejected, replay, duplicate, expired
expected_outcome: ACCEPTED      # or REJECTED
```

## Common Tasks

### Run Smoke Test
```python
exp = ScenarioLoader.load_from_file(config_path)
smoke = [e for e in exp if e.experiment_id == "smoke_test"][0]
# Execute and validate
```

### Compare Algorithms
```python
hmac_exp = create_experiment("HMAC_SHA256")
rsa_exp = create_experiment("RSA_PSS_SHA256")
ecdsa_exp = create_experiment("ECDSA_P256_SHA256")

for exp in [hmac_exp, rsa_exp, ecdsa_exp]:
    results = executor.execute(exp)
    summary = ResultValidator.summarize(ResultValidator.classify_batch(results, exp))
    print(f"{exp.experiment_id}: {summary['avg_latency_ms']:.1f}ms")
```

### Test Cache Impact
```python
exp_no_cache = create_experiment(cache_enabled=False)
exp_with_cache = create_experiment(cache_enabled=True)

results_no_cache = executor.execute(exp_no_cache)
results_with_cache = executor.execute(exp_with_cache)

# Compare latencies
```

### Test Cold vs Warm
```python
exp_cold = create_experiment(cold_start_mode=ColdStartMode.PER_ITERATION)
exp_warm = create_experiment(cold_start_mode=ColdStartMode.NONE)

results_cold = executor.execute(exp_cold)
results_warm = executor.execute(exp_warm)
```

### Test Key Rotation
```python
exp_no_rotation = create_experiment(
    rotation_mode=RotationMode.CURRENT_ONLY
)
exp_with_rotation = create_experiment(
    rotation_mode=RotationMode.CURRENT_AND_PREVIOUS
)
```

## Enumerations Reference

### Algorithm
- `Algorithm.HMAC_SHA256`
- `Algorithm.RSA_PSS_SHA256`
- `Algorithm.ECDSA_P256_SHA256`

### PayloadSize
- `PayloadSize.SMALL`
- `PayloadSize.MEDIUM`
- `PayloadSize.LARGE`

### ColdStartMode
- `ColdStartMode.NONE`
- `ColdStartMode.PER_ITERATION`
- `ColdStartMode.PER_EXPERIMENT`
- `ColdStartMode.IDLE_WAIT`

### RotationMode
- `RotationMode.CURRENT_ONLY`
- `RotationMode.CURRENT_AND_PREVIOUS`

### ExecutionMode
- `ExecutionMode.SEQUENTIAL`
- `ExecutionMode.CONCURRENT`

### ExpectedOutcome
- `ExpectedOutcome.ACCEPTED`
- `ExpectedOutcome.REJECTED`
- `ExpectedOutcome.INVALID_SIGNATURE`
- `ExpectedOutcome.REPLAY_DETECTED`
- `ExpectedOutcome.EXPIRED`

### ResultClassification
- `ResultClassification.SUCCESS`
- `ResultClassification.OUTCOME_MISMATCH`
- `ResultClassification.EXECUTION_ERROR`
- `ResultClassification.TIMEOUT`

## File Locations

| Component | File |
|-----------|------|
| Core models | `benchmark/models/experiment_definition.py` |
| Loader | `benchmark/models/scenario_loader.py` |
| Executor | `benchmark/models/scenario_executor.py` |
| Validator | `benchmark/models/result_validator.py` |
| Configurations | `benchmark/config/experiment_config_story14.yaml` |
| Examples | `benchmark/models/integration_examples.py` |
| Documentation | `.github/application_overhaul/story_no14/` |

## Key Methods

### ExperimentDefinition
- `compute_fingerprint()` - Get reproducible hash
- `to_dict()` - Export as dictionary
- `is_cold_start_scenario()` - Check if cold start
- `is_replay_scenario()` - Check if replay test
- `is_dedup_scenario()` - Check if dedup test

### ScenarioLoader
- `load_from_file(path)` - Load YAML experiments
- `_parse_experiment(dict)` - Parse single experiment

### ScenarioValidator
- `validate(exp)` - Validate single experiment
- `validate_all(exps)` - Validate multiple experiments

### ScenarioExecutor
- `execute(exp)` - Execute experiment
- `_execute_iteration(exp, iteration)` - Execute single iteration

### ResultValidator
- `classify(result, exp)` - Classify single result
- `classify_batch(results, exp)` - Classify multiple results
- `summarize(classified)` - Get summary statistics

## Example YAML

```yaml
experiments:
  - name: hmac_baseline
    description: "HMAC baseline with cold start"
    scenario: accepted
    algorithm: HMAC_SHA256
    payload_size: small
    iterations: 5
    expected_outcome: ACCEPTED
    cold_start_mode: per_iteration
    cache_enabled: false
    rotation_mode: current_only
    replay_enabled: true
    dedup_enabled: true
    execution_mode: sequential
    completion_timeout_seconds: 8.0
    poll_seconds: 0.25
    replay_window_ms: 300000
```

## Troubleshooting

### Import Error: yaml not found
```bash
pip install PyYAML
```

### Validation Errors
```python
errors = ScenarioValidator.validate_all(experiments)
for exp_id, error_list in errors.items():
    print(f"Experiment {exp_id}:")
    for error in error_list:
        print(f"  - {error}")
```

### Execution Failures
```python
results = executor.execute(experiment)
for result in results:
    if result.error:
        print(f"Iteration {result.iteration}: {result.error}")
```

## Available Experiments (37 Total)

### Baselines (6)
- baseline_hmac_cold, baseline_rsa_cold, baseline_ecdsa_cold
- warm_hmac_50, warm_rsa_50, warm_ecdsa_50

### Payload Tests (3)
- payload_hmac_small, payload_hmac_medium, payload_hmac_large

### Replay Tests (3)
- replay_hmac, replay_rsa, replay_ecdsa

### Duplicate Tests (3)
- duplicate_hmac, duplicate_rsa, duplicate_ecdsa

### Expiration Tests (3)
- expired_hmac, expired_rsa, expired_ecdsa

### Cache Tests (2) - NEW
- cache_disabled_hmac_cold, cache_enabled_hmac_cold

### Rotation Tests (2) - NEW
- rotation_current_only_hmac, rotation_current_and_previous_hmac

### Smoke Test (1)
- smoke_test

## Next Steps

1. **Load experiments** from Story 14 YAML files
2. **Validate** configurations before execution
3. **Execute** experiments with metadata logging
4. **Classify** results against expected outcomes
5. **Analyze** summary statistics
6. **Compare** across algorithm/payload/mode variations

## References

- **Full Implementation**: `STORY_14_IMPLEMENTATION.md`
- **User Guide**: `README.md`
- **Examples**: `benchmark/models/integration_examples.py`
- **Configuration**: `benchmark/config/experiment_config_story14.yaml`

