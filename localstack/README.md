# LocalStack Environment

This folder contains the local infrastructure bootstrap for the serverless platform.

## Defaults

- `AWS_REGION=eu-central-1`
- `LOCALSTACK_ENDPOINT=http://localhost:4566`
- `AWS_ACCESS_KEY_ID=test`
- `AWS_SECRET_ACCESS_KEY=test`

## Scripts

- `bootstrap.py`: idempotently creates required SQS, DynamoDB, and Secrets Manager resources, then wires ingress, accepted, and rejected SQS queues to the validation/persistence/audit Lambdas.
- `reset.py`: deletes required resources (if present) and recreates them.
- `smoke_test.py`: verifies required resources exist, secret payload schema is valid, and ingress/persistence/audit mappings are configured.

## Provisioned resources

- SQS: `thesis-ingress-events`, `thesis-accepted-events`, `thesis-rejected-events`
- DynamoDB: `thesis_ledger`, `thesis_dedup`, `thesis_audit`
- Secrets:
  - `thesis/hmac/current`
  - `thesis/hmac/previous`
  - `thesis/rsa/current`
  - `thesis/rsa/previous`
  - `thesis/ecdsa/current`
  - `thesis/ecdsa/previous`

Secret values are generated during bootstrap (no placeholder key material).

## Ingress wiring

- Event source mapping: `thesis-ingress-events -> thesis-validation`
- Mapping config: `BatchSize=1`, `Enabled=true`
- Bootstrap behavior is idempotent: it reuses existing mapping and enforces expected config.

`thesis-validation` must already exist in LocalStack before running `bootstrap.py`.

## Persistence wiring

- Event source mapping: `thesis-accepted-events -> thesis-persistence`
- Mapping config: `BatchSize=1`, `Enabled=true`
- Bootstrap behavior is idempotent: it reuses existing mapping and enforces expected config.

`thesis-persistence` must already exist in LocalStack before running `bootstrap.py`.

## Audit wiring

- Event source mapping: `thesis-rejected-events -> thesis-audit`
- Mapping config: `BatchSize=1`, `Enabled=true`
- Bootstrap behavior is idempotent: it reuses existing mapping and enforces expected config.

`thesis-audit` must already exist in LocalStack before running `bootstrap.py`.

## Quick start

```bash
docker compose up -d
python3 -m pip install -r localstack/requirements.txt
python3 localstack/bootstrap.py
python3 localstack/smoke_test.py
```

