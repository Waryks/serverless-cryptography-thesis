# Benchmark

Provisions a LocalStack environment and drives the Producer Lambda directly,
exercising the full pipeline: **Producer Lambda → SQS → Consumer Lambda → DynamoDB**.

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Docker (via Colima) | any recent |
| Colima | any recent |
| Python | 3.11+ |
| Java | 21 |

LocalStack is managed with plain `docker run` — no docker-compose needed.

Build all Lambda artifacts from the repo root:

```bash
mvn -q package -DskipTests -f pom.xml
```

Install Python deps:

```bash
pip install -r benchmark/requirements.txt
```

---

## Docker socket (Colima)

LocalStack needs a Docker socket to spin up Lambda containers.
The script always uses `/var/run/docker.sock` — this is the correct path
**inside containers** for both Colima and Docker Desktop.

> **Note:** `~/.colima/default/docker.sock` is the **host-side** socket used
> by the Docker CLI on macOS. It cannot be bind-mounted into a container —
> always use `/var/run/docker.sock` for container mounts.

Make sure Colima is running before executing the benchmark:

```bash
colima start
```

Use `--docker-socket` / `DOCKER_SOCKET` env var only if your setup uses a
non-standard socket path.

---

## Research variables

| Flag | Values | Thesis variable |
|------|--------|-----------------|
| `--algorithm` | `HMAC_SHA256` \| `RSA_PSS_SHA256` \| `ECDSA_P256_SHA256` | Cryptographic mechanism |
| `--cache-ttl` | `0` (baseline) / `>0` (mitigation) | `thesis.keys.cache.ttlSeconds` |
| `--cold-start` | flag | Stop + remove container → guaranteed partial cold start |
| `--warm-only` | flag | Reuse existing container → warm invocation baseline |
| `--invocations` | integer | Number of Lambda calls (more = better P95/P99 coverage) |
| `--native` | flag | Use GraalVM native binary instead of JVM jar (`provided.al2023` runtime) |
| `--localstack-host` | hostname/IP | LocalStack host (default: `localhost`) |
| `--docker-socket` | path | Docker socket override (default: auto-detected, see above) |

---

## Usage

```bash
# Baseline cold-start run for each algorithm (JVM)
python benchmark/run_benchmark.py --algorithm HMAC_SHA256       --cold-start
python benchmark/run_benchmark.py --algorithm RSA_PSS_SHA256    --cold-start
python benchmark/run_benchmark.py --algorithm ECDSA_P256_SHA256 --cold-start

# Mitigation: 60 s key cache, 50 warm invocations
python benchmark/run_benchmark.py --algorithm RSA_PSS_SHA256 --warm-only --cache-ttl 60 --invocations 50

# Native mode (build first — see Native Mode section below)
python benchmark/run_benchmark.py --native --algorithm HMAC_SHA256       --cold-start
python benchmark/run_benchmark.py --native --algorithm RSA_PSS_SHA256    --cold-start
python benchmark/run_benchmark.py --native --algorithm ECDSA_P256_SHA256 --cold-start

# Provision resources only (no Lambda invocations)
python benchmark/run_benchmark.py --provision-only

# LocalStack already running — skip docker run
python benchmark/run_benchmark.py --skip-start --algorithm HMAC_SHA256
```

---

## Native Mode (GraalVM)

The `--native` flag switches the Lambda runtime to `provided.al2023` and
expects Quarkus native binaries packaged as `function.zip`.

### Build

```bash
# Requires GraalVM / Mandrel with native-image installed
mvn -q package -Pnative -DskipTests -pl commons,producer-lambda,consumer-lambda
```

> **Heap / OOM:** Native image compilation is memory-intensive.
> If the build exits with code 137 (OOM), increase Docker/Colima memory:
> ```bash
> colima stop
> colima start --cpu 4 --memory 8
> ```
> Or raise the GraalVM heap explicitly in both module poms:
> ```xml
> <quarkus.native.native-image-xmx>6g</quarkus.native.native-image-xmx>
> ```

### Container spin-up warm-up

With the `provided.al2023` runtime, LocalStack starts the Lambda execution
environment container **on the first invocation**, not when the function
reports `State=Active`. This spin-up can take 60–120 s and would cause the
benchmark to appear frozen after the health-check line.

The script handles this automatically: before the measured loop begins it
issues a **throwaway warm-up invocation** with a 300 s timeout and retries
until it succeeds.  All subsequent measured invocations hit a running
container and return promptly.

---

## What gets provisioned

| Resource | Name |
|----------|------|
| SQS queue | `thesis-events` |
| Secrets Manager | `thesis/key/hmac-sha256`, `thesis/key/rsa-pss-sha256`, `thesis/key/ecdsa-p256-sha256` (+ `/public` variants for RSA and ECDSA) |
| DynamoDB | `thesis-dedup` (with TTL), `thesis-ledger` |
| Lambda | `producer`, `consumer` |
| SQS → Lambda trigger | `consumer` subscribed to `thesis-events` |

---

## Payload shape sent to the Producer Lambda

```json
{
  "content": {
    "eventId":          "<uuid>",
    "timestampEpochMs": 1700000000000,
    "algorithm":        "HMAC_SHA256",
    "keyId":            "thesis/key/hmac-sha256",
    "payload":          { "benchmarkRun": "<run-id>" }
  },
  "signatureB64": null
}
```

`signatureB64` is `null` — the **producer Lambda signs** the content.
This script is the benchmark client that provides the unsigned content.

---

## Attack Verification (`run_attacks.py`)

Confirms that the consumer Lambda correctly enforces all three security
mechanisms defined in the replay-protection model.

### Prerequisites

LocalStack must be running with all resources already provisioned:

```bash
python benchmark/run_benchmark.py --provision-only
```

### Attacks executed

| Name | What it does | Expected result |
|------|-------------|-----------------|
| `tampered` | Signs a valid event, then mutates `payload` before sending to SQS | Consumer rejects with `InvalidSignatureException` — event absent from ledger |
| `replay` | Sends the same `eventId` + signature twice | First accepted and written to ledger/dedup; second blocked by DynamoDB conditional write (`DuplicateEventException`) |
| `expired` | Sends a validly-signed event with `timestampEpochMs` outside the 300 s replay window | Consumer rejects with `ReplayWindowException` before touching DynamoDB — absent from both ledger and dedup |

### Verification method

For each attack the script:
1. Sends the crafted message **directly to SQS**, bypassing the producer Lambda for full control over the message body
2. Waits for the SQS → Lambda trigger to deliver and process it (default: 8 s)
3. Queries DynamoDB ledger and dedup tables to confirm presence/absence of the `eventId`
4. Reads LocalStack container logs to confirm the expected exception was raised

### Usage

```bash
# Run all three attacks with HMAC (default)
python benchmark/run_attacks.py

# Run with a different algorithm
python benchmark/run_attacks.py --algorithm RSA_PSS_SHA256
python benchmark/run_attacks.py --algorithm ECDSA_P256_SHA256

# Skip a specific attack
python benchmark/run_attacks.py --skip-attack replay

# Increase wait time if the consumer is slow to process
python benchmark/run_attacks.py --wait 15

# All three algorithms in sequence
for algo in HMAC_SHA256 RSA_PSS_SHA256 ECDSA_P256_SHA256; do
  python benchmark/run_attacks.py --algorithm $algo
done
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--algorithm` | `HMAC_SHA256` | Algorithm used to sign attack payloads |
| `--skip-attack` | — | Skip a named attack (repeatable): `tampered`, `replay`, `expired` |
| `--wait` | `8` | Seconds to wait for the consumer Lambda to process each message |
| `--localstack-host` | `localhost` | LocalStack hostname/IP |

### Exit code

`0` — all executed attacks passed  
`1` — one or more attacks failed (security mechanism not working as expected)
