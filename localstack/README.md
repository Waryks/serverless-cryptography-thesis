# LocalStack Story 1 Environment

This folder contains the local infrastructure bootstrap for Story 1.

## Defaults

- `AWS_REGION=eu-central-1`
- `LOCALSTACK_ENDPOINT=http://localhost:4566`
- `AWS_ACCESS_KEY_ID=test`
- `AWS_SECRET_ACCESS_KEY=test`

## Scripts

- `bootstrap.py`: idempotently creates required SQS, DynamoDB, and Secrets Manager resources.
- `reset.py`: deletes required resources (if present) and recreates them.
- `smoke_test.py`: verifies required resources exist and secret payload schema is valid.

## Provisioned resources (Story 1 plan contract)

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

## Quick start

```bash
docker compose up -d
python3 -m pip install -r localstack/requirements.txt
python3 localstack/bootstrap.py
python3 localstack/smoke_test.py
```

