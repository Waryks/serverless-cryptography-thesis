# Legacy Benchmark Runners

This directory contains the old benchmark runners that have been replaced by the Story 12 implementation.

## What Changed

**Old Runners** (archived here):
- `run_benchmark.py` — Legacy benchmark runner with CLI flags
- `run_attacks.py` — Attack verification script

**New Runner** (Story 12):
- `benchmark/runner/benchmark_runner.py` — Production-ready orchestrator
- 29 pre-configured experiments in YAML
- Comprehensive result analysis and export

## Why the Change

The Story 12 implementation provides:

1. **YAML Configuration** — Experiments defined in `benchmark/config/experiment_config.yaml`
2. **Modular Architecture** — 18 independent, testable modules
3. **Comprehensive Documentation** — 1,200+ lines of docs
4. **Better Metrics** — Percentiles, aggregation, end-to-end latency
5. **Multiple Output Formats** — CSV and JSON exports
6. **Cold-Start Support** — Multiple modes (per_iteration, per_experiment, idle_wait)
7. **Scenario Testing** — accepted, rejected, replay, duplicate, expired

## Using the New Runner

```bash
# Run all 29 experiments
python3 benchmark/runner/benchmark_runner.py

# Run specific experiment
python3 benchmark/runner/benchmark_runner.py --experiment smoke_test

# View results
cat benchmark/output/results/benchmark_results.csv
cat benchmark/output/results/benchmark_results.json
```

## If You Need the Old Runners

The old runners are still available here but are no longer the primary way to run benchmarks:

```bash
# These still work but are deprecated
python3 benchmark/.legacy/run_benchmark.py --provision-only
python3 benchmark/.legacy/run_attacks.py
```

## Migration Guide

| Old Command | New Command |
|-------------|-------------|
| `python3 benchmark/run_benchmark.py --provision-only` | `python3 benchmark/run_benchmark.py --provision-only` (still works) |
| `python3 benchmark/run_benchmark.py --algorithm HMAC_SHA256 --cold-start` | `python3 benchmark/runner/benchmark_runner.py --experiment baseline_hmac_cold` |
| `python3 benchmark/run_attacks.py` | Attacks are now part of benchmark scenarios: `replay_*`, `duplicate_*`, `expired_*` |

## All Functionality Preserved

Everything the old runners did is now covered:

- ✅ Event generation
- ✅ Lambda invocation
- ✅ Timing measurement
- ✅ Result collection
- ✅ Output export
- ✅ Scenario testing (replay, duplicate, expired)
- ✅ Algorithm variations
- ✅ Cold-start measurement

Plus new features:

- ✅ YAML configuration
- ✅ 29 pre-configured experiments
- ✅ Modular architecture
- ✅ Comprehensive metrics
- ✅ Better documentation
- ✅ Percentile statistics

## Story 12 Documentation

For complete documentation on the new system, see:
`/Users/sasha/Dev/repos/serverless-cryptography-thesis/.github/application_overhaul/story_no12/README.md`

