#!/usr/bin/env python3
"""
Benchmark runner for the serverless cryptography thesis.

End-to-end flow:
    This script  →  invoke Producer Lambda (with a SignedEvent)
                 →  Producer signs payload & publishes to SQS
                 →  Consumer Lambda (SQS trigger) verifies & writes to DynamoDB

Research variables (from .github/overall_implementation_details.md):
    --algorithm       HMAC_SHA256 | RSA_PSS_SHA256 | ECDSA_P256_SHA256
    --invocations     number of Lambda invocations per run
    --cache-ttl       thesis.keys.cache.ttlSeconds injected into both Lambdas
                      0  = no cache (baseline)
                      >0 = TTL-based key cache (mitigation)
    --cold-start      stop + remove the LocalStack container before the run
                      so the first invocation is a genuine partial cold start
    --warm-only       skip the restart; measure warm invocation latency only
    --native          build & deploy as GraalVM Native Image (provided.al2023 runtime)
                      instead of the default JVM mode (java21 runtime).
                      Requires Docker for the in-container native build.

LocalStack is started with the Docker socket mounted so Lambda containers
can be spawned via the Docker daemon. With Colima, /var/run/docker.sock
is the correct path inside containers:
    docker run -v /var/run/docker.sock:/var/run/docker.sock ...

Payload sent to the Producer Lambda (commons SignedEvent / SignedContent):
    {
      "content": {
        "eventId":          "<uuid>",
        "timestampEpochMs": <epoch ms>,
        "algorithm":        "HMAC_SHA256 | RSA_PSS_SHA256 | ECDSA_P256_SHA256",
        "keyId":            "<secrets-manager-secret-name>",
        "payload":          { "benchmarkRun": "<run-id>" }
      },
      "signatureB64": null      <- producer Lambda fills this in
    }

Secrets Manager secret schema (commons KeySecret record):
    { "keyId": "<name>", "algorithm": "<algo>", "keyMaterial": "<base64>" }

Usage:
    # Cold-start baseline for each algorithm (JVM mode — default)
    python benchmark/run_benchmark.py --algorithm HMAC_SHA256       --cold-start
    python benchmark/run_benchmark.py --algorithm RSA_PSS_SHA256    --cold-start
    python benchmark/run_benchmark.py --algorithm ECDSA_P256_SHA256 --cold-start

    # Same benchmarks in Native Image mode
    python benchmark/run_benchmark.py --algorithm HMAC_SHA256       --cold-start --native
    python benchmark/run_benchmark.py --algorithm RSA_PSS_SHA256    --cold-start --native
    python benchmark/run_benchmark.py --algorithm ECDSA_P256_SHA256 --cold-start --native

    # Mitigation: 60 s key cache, warm container, 50 invocations
    python benchmark/run_benchmark.py --algorithm RSA_PSS_SHA256 --warm-only --cache-ttl 60 --invocations 50

    # Provision resources only, do not invoke Lambdas
    python benchmark/run_benchmark.py --provision-only

    # LocalStack already running — skip docker run
    python benchmark/run_benchmark.py --skip-start --algorithm HMAC_SHA256
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Runtime globals — populated in main() from CLI args / env vars
# ---------------------------------------------------------------------------

LOCALSTACK_HOST: str     = ""   # e.g. "localhost"
LOCALSTACK_ENDPOINT: str = ""   # e.g. "http://localhost:4566"
DOCKER_SOCKET: str       = ""   # path to Docker socket
NATIVE_MODE: bool        = False  # True when --native is passed

# ---------------------------------------------------------------------------
# Static constants — must stay in sync with application.properties and commons
# ---------------------------------------------------------------------------

LOCALSTACK_CONTAINER_NAME = "localstack"
LOCALSTACK_IMAGE          = "localstack/localstack:latest"

AWS_REGION = "eu-central-1"

QUEUE_NAME             = "thesis-events"
DEDUP_TABLE            = "thesis-dedup"
LEDGER_TABLE           = "thesis-ledger"
PRODUCER_FUNCTION_NAME = "producer"
CONSUMER_FUNCTION_NAME = "consumer"
LAMBDA_ROLE_NAME       = "thesis-lambda-role"

# ---------------------------------------------------------------------------
# Runtime / artifact settings
# ---------------------------------------------------------------------------
LAMBDA_RUNTIME_JVM    = "java21"
LAMBDA_RUNTIME_NATIVE = "provided.al2023"
LAMBDA_HANDLER        = "io.quarkus.amazon.lambda.runtime.QuarkusStreamHandler::handleRequest"
LAMBDA_HANDLER_NATIVE = "not.used.in" + ".native.mode"   # native bootstrap ignores this


def _lambda_runtime() -> str:
    return LAMBDA_RUNTIME_NATIVE if NATIVE_MODE else LAMBDA_RUNTIME_JVM


def _lambda_handler() -> str:
    return LAMBDA_HANDLER_NATIVE if NATIVE_MODE else LAMBDA_HANDLER


def _runtime_label() -> str:
    return "native" if NATIVE_MODE else "JVM"

# One Secrets Manager secret per algorithm.
# HMAC   — symmetric: same secret used by producer and consumer.
# RSA/EC — asymmetric: producer uses <name>, consumer uses <name>/public.
KEY_SECRET_NAMES = {
    "HMAC_SHA256":       "thesis/key/hmac-sha256",
    "RSA_PSS_SHA256":    "thesis/key/rsa-pss-sha256",
    "ECDSA_P256_SHA256": "thesis/key/ecdsa-p256-sha256",
}

REPO_ROOT = Path(__file__).resolve().parent.parent

PRODUCER_ZIP = REPO_ROOT / "producer-lambda" / "target" / "function.zip"
CONSUMER_ZIP = REPO_ROOT / "consumer-lambda"  / "target" / "function.zip"

# Internal flag — prevents running the Maven build twice when both zips are missing
_artifacts_built: bool = False

# ---------------------------------------------------------------------------
# AWS client helpers
# ---------------------------------------------------------------------------

def _creds() -> dict:
    return dict(
        aws_access_key_id     = "test",
        aws_secret_access_key = "test",
        region_name           = AWS_REGION,
        endpoint_url          = LOCALSTACK_ENDPOINT,
    )

def _sqs():    return boto3.client("sqs",            **_creds())
def _sm():     return boto3.client("secretsmanager", **_creds())
def _dynamo(): return boto3.client("dynamodb",        **_creds())
def _lambda(): return boto3.client("lambda",          **_creds())
def _iam():    return boto3.client("iam",             **_creds())

def _lambda_invoke():
    """
    Lambda client used for *invocations* only.
    Uses a 300 s read timeout so that native cold-start container spin-up
    (which can take 60–120 s) does not cause boto3 to silently hang or abort.
    The default boto3 read timeout (60 s) is too short for the first native invoke.
    """
    return boto3.client(
        "lambda",
        config=BotocoreConfig(
            read_timeout=300,
            connect_timeout=10,
            retries={"max_attempts": 0},   # no automatic retries — we handle them ourselves
        ),
        **_creds(),
    )

# ---------------------------------------------------------------------------
# LocalStack lifecycle
# ---------------------------------------------------------------------------

def _resolve_docker_socket() -> str:
    """
    Return the Docker socket path to mount into the LocalStack container.

    /var/run/docker.sock is the correct path for both Colima and Docker Desktop —
    it is the socket that is accessible inside containers running on the VM.
    The ~/.colima/default/docker.sock file is the host-side socket used by the
    Docker CLI on macOS and cannot be bind-mounted into a container.

    An explicit override via --docker-socket / DOCKER_SOCKET is still accepted
    for non-standard setups.
    """
    if DOCKER_SOCKET:
        return DOCKER_SOCKET
    return "/var/run/docker.sock"


def start_localstack():
    socket = _resolve_docker_socket()
    # Native cold starts can take 60-120 s inside LocalStack-managed Lambda
    # containers.  The default LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT (≈25 s) is
    # far too short, causing "Timeout while starting up lambda environment".
    env_timeout = 300 if NATIVE_MODE else 120
    print(f"[localstack] Starting '{LOCALSTACK_CONTAINER_NAME}'  socket={socket}  "
          f"lambda_env_timeout={env_timeout}s")
    subprocess.run(
        [
            "docker", "run", "-d",
            "--name", LOCALSTACK_CONTAINER_NAME,
            "-p", "4566:4566",
            "-p", "4510-4559:4510-4559",
            "-e", "DEBUG=1",
            "-e", f"LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT={env_timeout}",
            "-v", f"{socket}:/var/run/docker.sock",
            LOCALSTACK_IMAGE,
        ],
        check=True,
    )


def stop_localstack():
    print(f"[localstack] Stopping '{LOCALSTACK_CONTAINER_NAME}' …")
    subprocess.run(["docker", "stop", LOCALSTACK_CONTAINER_NAME], check=False)
    subprocess.run(["docker", "rm",   LOCALSTACK_CONTAINER_NAME], check=False)


def wait_for_localstack(timeout: int = 120):
    import urllib.request
    required = {"sqs", "secretsmanager", "dynamodb", "lambda"}
    url      = f"{LOCALSTACK_ENDPOINT}/_localstack/health"
    print(f"[localstack] Waiting for health at {url} …", end="", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                services = json.loads(resp.read()).get("services", {})
                if all(services.get(s) in ("running", "available") for s in required):
                    print(" ready.")
                    return
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(3)
    print()
    sys.exit(f"[ERROR] Timed out waiting for LocalStack at {url}")

# ---------------------------------------------------------------------------
# Key material generation
# ---------------------------------------------------------------------------

def _hmac_key_b64() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def _rsa_keypair_b64() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
    from cryptography.hazmat.primitives import serialization
    priv    = generate_private_key(public_exponent=65537, key_size=2048)
    priv_b64 = base64.b64encode(priv.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())).decode()
    pub_b64  = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    return priv_b64, pub_b64


def _ec_keypair_b64() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
    from cryptography.hazmat.primitives import serialization
    priv    = generate_private_key(SECP256R1())
    priv_b64 = base64.b64encode(priv.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())).decode()
    pub_b64  = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    return priv_b64, pub_b64

# ---------------------------------------------------------------------------
# Resource provisioning
# ---------------------------------------------------------------------------

def _ensure_iam_role() -> str:
    iam    = _iam()
    assume = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    })
    try:
        arn = iam.create_role(RoleName=LAMBDA_ROLE_NAME,
                              AssumeRolePolicyDocument=assume)["Role"]["Arn"]
        print(f"[iam]    Created role {arn}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=LAMBDA_ROLE_NAME)["Role"]["Arn"]
        else:
            raise
    return arn


def provision_secrets():
    """
    Seed Secrets Manager with one KeySecret per algorithm.
    Schema: { keyId, algorithm, keyMaterial } — matches commons KeySecret record.
    """
    sm = _sm()

    def _upsert(name: str, value: dict):
        body = json.dumps(value)
        try:
            sm.create_secret(Name=name, SecretString=body)
            print(f"[secrets] Created  '{name}'")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ResourceExistsException", "AlreadyExistsException"):
                sm.put_secret_value(SecretId=name, SecretString=body)
                print(f"[secrets] Updated  '{name}'")
            else:
                raise

    _upsert(KEY_SECRET_NAMES["HMAC_SHA256"], {
        "keyId": KEY_SECRET_NAMES["HMAC_SHA256"],
        "algorithm": "HMAC_SHA256",
        "keyMaterial": _hmac_key_b64(),
    })

    rsa_priv, rsa_pub = _rsa_keypair_b64()
    _upsert(KEY_SECRET_NAMES["RSA_PSS_SHA256"], {
        "keyId": KEY_SECRET_NAMES["RSA_PSS_SHA256"],
        "algorithm": "RSA_PSS_SHA256",
        "keyMaterial": rsa_priv,
    })
    _upsert(KEY_SECRET_NAMES["RSA_PSS_SHA256"] + "/public", {
        "keyId": KEY_SECRET_NAMES["RSA_PSS_SHA256"] + "/public",
        "algorithm": "RSA_PSS_SHA256",
        "keyMaterial": rsa_pub,
    })

    ec_priv, ec_pub = _ec_keypair_b64()
    _upsert(KEY_SECRET_NAMES["ECDSA_P256_SHA256"], {
        "keyId": KEY_SECRET_NAMES["ECDSA_P256_SHA256"],
        "algorithm": "ECDSA_P256_SHA256",
        "keyMaterial": ec_priv,
    })
    _upsert(KEY_SECRET_NAMES["ECDSA_P256_SHA256"] + "/public", {
        "keyId": KEY_SECRET_NAMES["ECDSA_P256_SHA256"] + "/public",
        "algorithm": "ECDSA_P256_SHA256",
        "keyMaterial": ec_pub,
    })


def provision_sqs() -> str:
    url = _sqs().create_queue(QueueName=QUEUE_NAME)["QueueUrl"]
    print(f"[sqs]    Queue ready: {url}")
    return url


def provision_dynamo():
    ddb = _dynamo()
    for table in (DEDUP_TABLE, LEDGER_TABLE):
        try:
            ddb.create_table(
                TableName            = table,
                KeySchema            = [{"AttributeName": "eventId", "KeyType": "HASH"}],
                AttributeDefinitions = [{"AttributeName": "eventId", "AttributeType": "S"}],
                BillingMode          = "PAY_PER_REQUEST",
            )
            print(f"[dynamo] Created table '{table}'")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceInUseException":
                print(f"[dynamo] Table '{table}' already exists — skipping")
            else:
                raise
    try:
        ddb.update_time_to_live(
            TableName                = DEDUP_TABLE,
            TimeToLiveSpecification  = {"Enabled": True, "AttributeName": "ttl"},
        )
    except ClientError:
        pass


def _wait_for_lambda_updatable(name: str, timeout: int = 60):
    """
    Wait until the Lambda's LastUpdateStatus is no longer 'InProgress'.
    AWS (and LocalStack) reject update_function_code / update_function_configuration
    with ResourceConflictException if a previous update is still being applied.
    """
    lam      = _lambda()
    deadline = time.time() + timeout
    while time.time() < deadline:
        cfg    = lam.get_function_configuration(FunctionName=name)
        status = cfg.get("LastUpdateStatus", "Successful")
        if status != "InProgress":
            return
        time.sleep(2)
    sys.exit(f"[ERROR] Timed out waiting for Lambda '{name}' to finish updating.")


def build_artifacts():
    """
    Build producer-lambda and consumer-lambda with Maven.

    In JVM mode (default):
        mvn package -DskipTests

    In native mode (--native):
        mvn package -DskipTests -Dnative -Dquarkus.native.container-build=true
        This produces a Linux-amd64 native executable inside a Docker container,
        which is required when building on macOS / non-Linux hosts.

    Called automatically by provision_lambda() when the expected zip is not
    found, so the user never needs to run mvn manually.
    Guarded by _artifacts_built so the Maven build only runs once even when
    both producer and consumer zips are missing.
    """
    global _artifacts_built
    if _artifacts_built:
        return
    _artifacts_built = True

    cmd = [
        "mvn", "--no-transfer-progress", "-q",
        "package", "-DskipTests",
        "-pl", "commons,producer-lambda,consumer-lambda",
    ]

    if NATIVE_MODE:
        cmd += ["-Dnative", "-Dquarkus.native.container-build=true"]

    mode_label = _runtime_label()
    print(f"\n[build] Building artifacts  mode={mode_label}")
    print(f"[build] Command: {' '.join(cmd)}\n")

    result = subprocess.run(cmd, cwd=REPO_ROOT)
    if result.returncode != 0:
        sys.exit(
            f"[ERROR] Maven build failed (exit code {result.returncode}).\n"
            f"        Run manually to see full output:\n"
            f"        {' '.join(cmd)}"
        )
    print(f"[build] Build successful ({mode_label}).\n")


def _host_architecture() -> str:
    """
    Return the Lambda-API architecture string that matches the host machine.
    Native images built with -Dquarkus.native.container-build=true compile for
    the host's architecture, so the Lambda function must be created with a
    matching Architectures value.  JVM mode is architecture-agnostic.
    """
    import platform
    machine = platform.machine().lower()
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return "x86_64"


def provision_lambda(name: str, zip_path: Path, role_arn: str, env_vars: dict):
    if not zip_path.exists():
        print(f"[build] Artifact not found: {zip_path}")
        build_artifacts()
        if not zip_path.exists():
            sys.exit(
                f"[ERROR] Artifact still missing after build: {zip_path}\n"
                f"        Check Maven output above for compilation errors."
            )

    runtime = _lambda_runtime()
    handler = _lambda_handler()
    timeout    = 300 if NATIVE_MODE else 60    # native cold starts need more headroom in LocalStack
    memory_mb  = 1024 if NATIVE_MODE else 512  # extra memory helps native startup speed
    arch       = _host_architecture() if NATIVE_MODE else "x86_64"

    lam   = _lambda()
    zdata = zip_path.read_bytes()
    try:
        resp = lam.create_function(
            FunctionName  = name,
            Runtime       = runtime,
            Role          = role_arn,
            Handler       = handler,
            Code          = {"ZipFile": zdata},
            Timeout       = timeout,
            MemorySize    = memory_mb,
            Architectures = [arch],
            Environment   = {"Variables": env_vars},
        )
        print(f"[lambda] Created '{name}' ({resp['FunctionArn']})  runtime={runtime}  arch={arch}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceConflictException":
            # Function already exists — update code first, wait, then update config
            _wait_for_lambda_updatable(name)
            lam.update_function_code(FunctionName=name, ZipFile=zdata, Architectures=[arch])
            _wait_for_lambda_updatable(name)
            lam.update_function_configuration(
                FunctionName = name,
                Runtime      = runtime,
                Handler      = handler,
                Environment  = {"Variables": env_vars},
            )
            print(f"[lambda] Updated '{name}'  runtime={runtime}  arch={arch}")
        else:
            raise


def provision_sqs_trigger(queue_url: str):
    q_arn = _sqs().get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    try:
        _lambda().create_event_source_mapping(
            EventSourceArn        = q_arn,
            FunctionName          = CONSUMER_FUNCTION_NAME,
            BatchSize             = 10,
            Enabled               = True,
            FunctionResponseTypes = ["ReportBatchItemFailures"],
        )
        print(f"[lambda] SQS -> '{CONSUMER_FUNCTION_NAME}' event-source mapping created (partial batch response enabled)")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceConflictException":
            print("[lambda] Event-source mapping already exists — skipping")
        else:
            raise


def _localstack_container_ip() -> str:
    """
    Return the Docker bridge IP of the running LocalStack container.
    Lambda containers are spawned on the same bridge network by LocalStack,
    so they must reach LocalStack via its container IP — not via 'localhost',
    which resolves to the Lambda container itself.
    """
    try:
        result = subprocess.run(
            [
                "docker", "inspect",
                "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                LOCALSTACK_CONTAINER_NAME,
            ],
            capture_output=True, text=True, check=True,
        )
        ip = result.stdout.strip()
        if not ip:
            sys.exit(f"[ERROR] Could not determine IP of container '{LOCALSTACK_CONTAINER_NAME}'. "
                     f"Is it running?")
        print(f"[localstack] Container IP: {ip}")
        return ip
    except Exception as e:
        sys.exit(f"[ERROR] Failed to inspect LocalStack container IP: {e}")


def provision_all(cache_ttl: int) -> str:
    role_arn  = _ensure_iam_role()
    queue_url = provision_sqs()
    provision_secrets()
    provision_dynamo()

    # The script's boto3 calls use LOCALSTACK_ENDPOINT (http://localhost:4566).
    # Lambda containers however run on the same Docker bridge network as LocalStack
    # and cannot use 'localhost' — they must reach LocalStack via its container IP.
    container_ip       = _localstack_container_ip()
    lambda_ls_endpoint = f"http://{container_ip}:4566"

    env = {
        "QUARKUS_SECRETSMANAGER_ENDPOINT_OVERRIDE": lambda_ls_endpoint,
        "QUARKUS_SQS_ENDPOINT_OVERRIDE":            lambda_ls_endpoint,
        "QUARKUS_DYNAMODB_ENDPOINT_OVERRIDE":       lambda_ls_endpoint,
        "QUARKUS_SQS_AWS_REGION":                   AWS_REGION,
        "QUARKUS_SECRETSMANAGER_AWS_REGION":        AWS_REGION,
        "QUARKUS_DYNAMODB_AWS_REGION":              AWS_REGION,
        "THESIS_SQS_QUEUE_NAME":                    QUEUE_NAME,
        "THESIS_KEYS_CACHE_TTLSECONDS":             str(cache_ttl),
        "THESIS_REPLAY_CHECK_ENABLED":              "true",
        "THESIS_REPLAY_CHECK_WINDOW_MS":            "300000",
        "THESIS_DYNAMODB_LEDGER_TABLE":             LEDGER_TABLE,
        "THESIS_DYNAMODB_DEDUP_TABLE":              DEDUP_TABLE,
        "THESIS_DYNAMODB_DEDUP_TTL_SECONDS":        "300",
    }

    # Quarkus native Lambda requires DISABLE_SIGNAL_HANDLERS to avoid hanging
    # during startup inside the Lambda container (see manage.sh / sam.native.yaml).
    if NATIVE_MODE:
        env["DISABLE_SIGNAL_HANDLERS"] = "true"

    provision_lambda(PRODUCER_FUNCTION_NAME, PRODUCER_ZIP, role_arn, env)
    provision_lambda(CONSUMER_FUNCTION_NAME, CONSUMER_ZIP, role_arn, env)
    provision_sqs_trigger(queue_url)
    return queue_url

# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------

def _fetch_localstack_logs(function_name: str, lines: int = 50) -> str:
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", "200", LOCALSTACK_CONTAINER_NAME],
            capture_output=True, text=True,
        )
        relevant = [
            line for line in (result.stdout + result.stderr).splitlines()
            if function_name in line or "ERROR" in line or "error" in line
        ]
        return "\n".join(relevant[-lines:]) or "(no relevant log lines found)"
    except Exception as e:
        return f"(could not fetch logs: {e})"


def _wait_for_lambda_active(function_name: str, timeout: int = None):
    """Poll until Active; abort with container logs on Failed."""
    if timeout is None:
        timeout = 300 if NATIVE_MODE else 60
    lam      = _lambda()
    deadline = time.time() + timeout
    print(f"[health] Waiting for Lambda '{function_name}' …", end="", flush=True)
    while time.time() < deadline:
        cfg   = lam.get_function_configuration(FunctionName=function_name)
        state = cfg.get("State")
        if state == "Active":
            print(" Active ✓")
            return
        if state == "Failed":
            print(" Failed ✗")
            print(f"\n[ERROR] Lambda '{function_name}' failed to start.")
            print(f"[ERROR] Reason : {cfg.get('StateReason', 'unknown')}")
            print(f"\n--- LocalStack logs (filtered for '{function_name}') ---")
            print(_fetch_localstack_logs(function_name))
            print("---")
            sys.exit(1)
        print(".", end="", flush=True)
        time.sleep(3)
    print()
    sys.exit(f"[ERROR] Timed out waiting for Lambda '{function_name}' to become Active.")


def health_check(queue_url: str):
    print("\n[health] Verifying all resources …")
    errors: list[str] = []

    try:
        _sqs().get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
        print(f"[health] SQS '{QUEUE_NAME}' ✓")
    except Exception as e:
        errors.append(f"SQS: {e}")

    for algo, name in KEY_SECRET_NAMES.items():
        try:
            _sm().describe_secret(SecretId=name)
            print(f"[health] Secret '{name}' ({algo}) ✓")
        except Exception as e:
            errors.append(f"Secret '{name}': {e}")

    for table in (DEDUP_TABLE, LEDGER_TABLE):
        try:
            status = _dynamo().describe_table(TableName=table)["Table"]["TableStatus"]
            print(f"[health] DynamoDB '{table}' ({status}) ✓")
        except Exception as e:
            errors.append(f"DynamoDB '{table}': {e}")

    if errors:
        print("\n[health] Failures:")
        for err in errors:
            print(f"  x {err}")
        sys.exit(1)

    # Lambda checks last — they involve polling and may print logs on failure
    for fn in (PRODUCER_FUNCTION_NAME, CONSUMER_FUNCTION_NAME):
        _wait_for_lambda_active(fn)

    print("[health] All resources healthy.\n")

# ---------------------------------------------------------------------------
# Cache-TTL hot-update (warm-only scenario)
# ---------------------------------------------------------------------------

def update_cache_ttl(cache_ttl: int):
    """Update only the cache TTL env var on both Lambdas, preserving all other env vars."""
    lam = _lambda()
    for fn in (PRODUCER_FUNCTION_NAME, CONSUMER_FUNCTION_NAME):
        _wait_for_lambda_updatable(fn)
        cfg = lam.get_function_configuration(FunctionName=fn)
        env = cfg.get("Environment", {}).get("Variables", {})
        env["THESIS_KEYS_CACHE_TTLSECONDS"] = str(cache_ttl)
        lam.update_function_configuration(FunctionName=fn, Environment={"Variables": env})
    print(f"[lambda] Cache TTL updated to {cache_ttl}s on both functions")

# ---------------------------------------------------------------------------
# Benchmark invocations
# ---------------------------------------------------------------------------

def _build_payload(algorithm: str, key_id: str, run_id: str) -> dict:
    """
    Build the SignedEvent JSON sent to the Producer Lambda.
    Matches commons SignedEvent / SignedContent records exactly.
    signatureB64 is null — the producer Lambda performs the signing.
    """
    return {
        "content": {
            "eventId":          str(uuid.uuid4()),
            "timestampEpochMs": int(time.time() * 1000),
            "algorithm":        algorithm,
            "keyId":            key_id,
            "payload":          {"benchmarkRun": run_id},
        },
        "signatureB64": None,
    }


def _invoke_producer(payload: dict) -> dict:
    resp = _lambda_invoke().invoke(
        FunctionName   = PRODUCER_FUNCTION_NAME,
        InvocationType = "RequestResponse",
        Payload        = json.dumps(payload).encode(),
    )
    body = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise RuntimeError(f"Lambda error: {body.decode()}")
    return json.loads(body)


def run_benchmark(algorithm: str, invocations: int, run_id: str) -> list[dict]:
    """Invoke the Producer Lambda and collect ProducerResponse objects."""
    key_id  = KEY_SECRET_NAMES[algorithm]
    results = []

    print(f"\n[bench]  algorithm={algorithm}  invocations={invocations}  run={run_id}  runtime={_runtime_label()}")
    print(f"[bench]  keyId={key_id}")
    print("-" * 60)

    for i in range(1, invocations + 1):
        try:
            response = _invoke_producer(_build_payload(algorithm, key_id, run_id))
            cold_tag = "COLD" if response.get("coldStart") else "warm"
            print(
                f"  [{i:>4}/{invocations}] {cold_tag:<4}  "
                f"eventId={str(response.get('eventId', '?'))[:8]}...  "
                f"durationMs={response.get('durationMs', '?')}"
            )
            results.append({"invocation": i, **response})
        except Exception as exc:
            print(f"  [{i:>4}/{invocations}] ERROR: {exc}")
            results.append({"invocation": i, "error": str(exc)})

    return results


def print_summary(results: list[dict], algorithm: str, cache_ttl: int):
    def _stats(vals: list) -> str:
        if not vals:
            return "n/a"
        s = sorted(vals)
        n = len(s)
        return (f"avg={sum(s)/n:.1f}  p50={s[n//2]}  "
                f"p95={s[int(n * 0.95)]}  p99={s[int(n * 0.99)]}  (n={n})  [ms]")

    all_ms  = [r["durationMs"] for r in results if "durationMs" in r]
    cold_ms = [r["durationMs"] for r in results if r.get("coldStart") and "durationMs" in r]
    warm_ms = [r["durationMs"] for r in results if not r.get("coldStart") and "durationMs" in r]
    errors  = [r for r in results if "error" in r]

    print("\n" + "=" * 60)
    print(f"  RESULTS  algorithm={algorithm}  cache-ttl={cache_ttl}s  runtime={_runtime_label()}")
    print("=" * 60)
    print(f"  Total invocations : {len(results)}")
    print(f"  Errors            : {len(errors)}")
    print(f"  Cold starts       : {len(cold_ms)}")
    print(f"  All latency       : {_stats(all_ms)}")
    if cold_ms:
        print(f"  Cold latency      : {_stats(cold_ms)}")
    if warm_ms:
        print(f"  Warm latency      : {_stats(warm_ms)}")
    print("=" * 60 + "\n")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

ALGORITHMS = ["HMAC_SHA256", "RSA_PSS_SHA256", "ECDSA_P256_SHA256"]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Thesis benchmark — provision LocalStack and invoke the Producer Lambda.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Research variables (thesis specification):
  --algorithm    Cryptographic mechanism: HMAC_SHA256 | RSA_PSS_SHA256 | ECDSA_P256_SHA256
  --cache-ttl    Key-cache TTL: 0=baseline (no cache), >0=mitigation
  --cold-start   Restart LocalStack -> guaranteed partial cold start
  --warm-only    Reuse container -> warm invocation latency only
  --native       Build & deploy as GraalVM Native Image (provided.al2023)
  --invocations  Sample size for percentile calculations (P50/P95/P99)

Examples:
  # Cold-start baseline for each algorithm (JVM)
  python run_benchmark.py --algorithm HMAC_SHA256       --cold-start
  python run_benchmark.py --algorithm RSA_PSS_SHA256    --cold-start
  python run_benchmark.py --algorithm ECDSA_P256_SHA256 --cold-start

  # Same benchmarks in Native Image mode
  python run_benchmark.py --algorithm HMAC_SHA256       --cold-start --native
  python run_benchmark.py --algorithm RSA_PSS_SHA256    --cold-start --native
  python run_benchmark.py --algorithm ECDSA_P256_SHA256 --cold-start --native

  # Mitigation: 60 s key cache, warm container, 50 invocations
  python run_benchmark.py --algorithm RSA_PSS_SHA256 --warm-only --cache-ttl 60 --invocations 50

  # Provision resources only, do not invoke Lambdas
  python run_benchmark.py --provision-only

  # LocalStack already running — skip docker run
  python run_benchmark.py --skip-start --algorithm HMAC_SHA256
        """,
    )
    parser.add_argument(
        "--algorithm",
        choices=ALGORITHMS,
        default="HMAC_SHA256",
        help="Cryptographic algorithm (default: HMAC_SHA256)",
    )
    parser.add_argument(
        "--invocations",
        type=int,
        default=20,
        help="Number of Lambda invocations (default: 20)",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Key-cache TTL: 0=off/baseline, >0=on/mitigation (default: 0)",
    )
    parser.add_argument(
        "--native",
        action="store_true",
        default=False,
        help=(
            "Build and deploy as GraalVM Native Image instead of JVM. "
            "Uses provided.al2023 runtime and -Dnative Maven profile. "
            "Requires Docker for the in-container native compilation."
        ),
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--cold-start",
        action="store_true",
        help="Stop + remove LocalStack before the run (guaranteed partial cold start).",
    )
    mode.add_argument(
        "--warm-only",
        action="store_true",
        help="Skip LocalStack restart; measure warm invocation latency only.",
    )

    parser.add_argument(
        "--skip-start",
        action="store_true",
        help="Do not manage the LocalStack container (already running externally).",
    )
    parser.add_argument(
        "--provision-only",
        action="store_true",
        help="Provision resources and run health checks, then exit without invoking Lambdas.",
    )
    parser.add_argument(
        "--localstack-host",
        default=os.environ.get("LOCALSTACK_HOST", "localhost"),
        metavar="HOST",
        help="LocalStack hostname/IP (default: localhost or LOCALSTACK_HOST env var)",
    )
    parser.add_argument(
        "--docker-socket",
        default=os.environ.get("DOCKER_SOCKET", ""),
        metavar="PATH",
        help=(
            "Docker socket path mounted into LocalStack for Lambda execution. "
            "Defaults to /var/run/docker.sock, which works for both Colima and "
            "Docker Desktop. Override via DOCKER_SOCKET env var only if your "
            "setup uses a non-standard socket path."
        ),
    )
    return parser.parse_args()


def main():
    args   = parse_args()
    run_id = str(uuid.uuid4())[:8]

    global LOCALSTACK_HOST, LOCALSTACK_ENDPOINT, DOCKER_SOCKET, NATIVE_MODE
    global _artifacts_built
    _artifacts_built = False

    LOCALSTACK_HOST     = args.localstack_host
    LOCALSTACK_ENDPOINT = f"http://{LOCALSTACK_HOST}:4566"
    DOCKER_SOCKET       = args.docker_socket
    NATIVE_MODE         = args.native

    print(f"\n{'='*60}")
    print(f"  Thesis Benchmark  —  run_id={run_id}")
    print(f"  algorithm    : {args.algorithm}")
    print(f"  invocations  : {args.invocations}")
    print(f"  cache-ttl    : {args.cache_ttl}s")
    print(f"  cold-start   : {args.cold_start}")
    print(f"  runtime      : {_runtime_label()} ({_lambda_runtime()})")
    print(f"  localstack   : {LOCALSTACK_ENDPOINT}")
    print(f"  docker socket: {_resolve_docker_socket()}")
    print(f"{'='*60}\n")

    # ── LocalStack lifecycle ────────────────────────────────────────────────
    if not args.skip_start:
        if args.cold_start:
            try:
                stop_localstack()
            except Exception:
                pass
            start_localstack()
        elif not args.warm_only:
            start_localstack()

    wait_for_localstack()

    # ── Provision ───────────────────────────────────────────────────────────
    queue_url = provision_all(cache_ttl=args.cache_ttl)

    if args.warm_only:
        update_cache_ttl(args.cache_ttl)

    # ── Health checks ────────────────────────────────────────────────────────
    health_check(queue_url)

    if args.provision_only:
        print("[bench] --provision-only: done.")
        return

    # ── Run ─────────────────────────────────────────────────────────────────
    results = run_benchmark(args.algorithm, args.invocations, run_id)
    print_summary(results, algorithm=args.algorithm, cache_ttl=args.cache_ttl)


if __name__ == "__main__":
    main()

