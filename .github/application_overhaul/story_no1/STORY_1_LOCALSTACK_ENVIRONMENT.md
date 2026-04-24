# Story 1 — Create Base LocalStack Environment

## Goal

Create a repeatable local development environment that allows all serverless components to be tested without deploying to real AWS.

The environment must support:

- Lambda execution
- SQS queues
- DynamoDB tables
- Secrets Manager secrets
- SQS → Lambda event source mappings
- local bootstrap/reset scripts
- local smoke testing

This story prepares the infrastructure foundation for the rest of the thesis project.

---

## Why this story matters

The thesis requires controlled performance experiments. Manual setup would introduce inconsistency and make benchmarking unreliable.

This story ensures that every experiment starts from a known state:

```
docker compose up
bootstrap script
run smoke test
```

The same environment should be usable by developers, agents, and benchmark scripts.

---

## Expected project structure

```
serverless-cryptography-thesis/
│
├── common/
├── producer-lambda/
├── validation-lambda/
├── persistence-lambda/
├── audit-lambda/
├── benchmark/
├── localstack/
├── docker-compose.yml
├── pom.xml
└── README.md
```

---

## Required LocalStack services

- lambda  
- sqs  
- dynamodb  
- secretsmanager  
- iam  
- logs  
- sts  

Region: `eu-central-1`  
Endpoint: `http://localhost:4566`

---

## Required queues

- thesis-ingress-events  
- thesis-accepted-events  
- thesis-rejected-events  

---

## Required DynamoDB tables

- thesis_ledger  
- thesis_dedup  
- thesis_audit  

Primary key: `eventId (string)`

---

## Required Secrets

```
thesis/hmac/current
thesis/hmac/previous
thesis/rsa/current
thesis/rsa/previous
thesis/ecdsa/current
thesis/ecdsa/previous
```

Example value:

```json
{
  "keyId": "hmac-current-local",
  "algorithm": "HMAC_SHA256",
  "keyMaterial": "PLACEHOLDER"
}
```

---

## Required scripts

```
localstack/
├── bootstrap.py
├── reset.py
└── smoke_test.py
```

### bootstrap.py

- create queues
- create tables
- create secrets
- idempotent

### reset.py

- delete & recreate resources

### smoke_test.py

- verify queues
- verify tables
- verify secrets

---

## docker-compose.yml

Expose LocalStack on port 4566.

---

## Configuration

```
AWS_REGION=eu-central-1
LOCALSTACK_ENDPOINT=http://localhost:4566
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
```

---

## Future Lambda names

- thesis-producer  
- thesis-validation  
- thesis-persistence  
- thesis-audit  

---

## Acceptance criteria

- LocalStack starts
- Resources are created
- Scripts are idempotent
- Smoke test passes

---

## Out of scope

- crypto logic
- lambda logic
- benchmarking
