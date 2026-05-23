# Benchmark Runner Documentation

## Purpose

This document provides the implementation-level overview for the benchmark framework used in the thesis project.

## What the Benchmark Framework Does

The benchmark framework coordinates reproducible experiment runs across the serverless pipeline and records timing and outcome data for analysis.

### Capabilities

- generate benchmark events
- invoke the producer Lambda
- wait for accepted and rejected processing to complete
- collect latency and outcome metrics
- export results as CSV and JSON
- support accepted, rejected, replay, duplicate, and expired-event scenarios
- support cold and warm execution modes

## Core Modules

- `benchmark/runner/` — orchestration and execution
- `benchmark/generators/` — event and payload generation
- `benchmark/scenarios/` — benchmark and attack scenarios
- `benchmark/collectors/` — result collection
- `benchmark/metrics/` — statistics and percentiles
- `benchmark/output/` — result exporters
- `benchmark/config/` — experiment definitions

## Configuration and Outputs

- `benchmark/config/experiment_config.yaml` contains the experiment catalog.
- `benchmark/output/results/` contains generated CSV and JSON results.
- `benchmark/verify_models.py` performs the lightweight model verification check.

## Related Documentation

- `benchmark/README.md` — main benchmark usage guide
- `docs/thesis-scope.md` — broader research scope and system overview
- `localstack/README.md` — LocalStack setup required by benchmark runs

