#!/usr/bin/env python3
"""Provision LocalStack resources for Story 1.

The script is intentionally idempotent so it can be re-run before every test.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key as generate_private_key_ec
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_private_key_rsa

QUEUE_NAMES = [
    "thesis-ingress-events",
    "thesis-accepted-events",
    "thesis-rejected-events",
]

INGRESS_QUEUE_NAME = "thesis-ingress-events"
VALIDATION_FUNCTION_NAME = "thesis-validation"
ACCEPTED_QUEUE_NAME = "thesis-accepted-events"
PERSISTENCE_FUNCTION_NAME = "thesis-persistence"
REJECTED_QUEUE_NAME = "thesis-rejected-events"
AUDIT_FUNCTION_NAME = "thesis-audit"
INGRESS_MAPPING_BATCH_SIZE = 1
ACCEPTED_MAPPING_BATCH_SIZE = 1
REJECTED_MAPPING_BATCH_SIZE = 1

TABLE_NAMES = [
    "thesis_ledger",
    "thesis_dedup",
    "thesis_audit",
]

SECRET_NAMES = [
    "thesis/hmac/current",
    "thesis/hmac/previous",
    "thesis/rsa/current",
    "thesis/rsa/previous",
    "thesis/ecdsa/current",
    "thesis/ecdsa/previous",
]


def _hmac_key_b64() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


def _rsa_keypair_b64() -> tuple[str, str]:
    private_key = generate_private_key_rsa(public_exponent=65537, key_size=2048)
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return (
        base64.b64encode(public_der).decode("ascii"),
        base64.b64encode(private_der).decode("ascii"),
    )


def _ec_keypair_b64() -> tuple[str, str]:
    private_key = generate_private_key_ec(SECP256R1())
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return (
        base64.b64encode(public_der).decode("ascii"),
        base64.b64encode(private_der).decode("ascii"),
    )


def generate_secrets_payloads() -> dict[str, dict[str, str]]:
    _, rsa_current_private_b64 = _rsa_keypair_b64()
    _, rsa_previous_private_b64 = _rsa_keypair_b64()
    _, ec_current_private_b64 = _ec_keypair_b64()
    _, ec_previous_private_b64 = _ec_keypair_b64()

    return {
        "thesis/hmac/current": {
            "keyId": "thesis/hmac/current",
            "algorithm": "HMAC_SHA256",
            "keyMaterial": _hmac_key_b64(),
        },
        "thesis/hmac/previous": {
            "keyId": "thesis/hmac/previous",
            "algorithm": "HMAC_SHA256",
            "keyMaterial": _hmac_key_b64(),
        },
        "thesis/rsa/current": {
            "keyId": "thesis/rsa/current",
            "algorithm": "RSA_PSS_SHA256",
            "keyMaterial": rsa_current_private_b64,
        },
        "thesis/rsa/previous": {
            "keyId": "thesis/rsa/previous",
            "algorithm": "RSA_PSS_SHA256",
            "keyMaterial": rsa_previous_private_b64,
        },
        "thesis/ecdsa/current": {
            "keyId": "thesis/ecdsa/current",
            "algorithm": "ECDSA_P256_SHA256",
            "keyMaterial": ec_current_private_b64,
        },
        "thesis/ecdsa/previous": {
            "keyId": "thesis/ecdsa/previous",
            "algorithm": "ECDSA_P256_SHA256",
            "keyMaterial": ec_previous_private_b64,
        },
    }


@dataclass(frozen=True)
class Config:
    aws_region: str
    endpoint_url: str
    access_key_id: str
    secret_access_key: str


def load_config() -> Config:
    return Config(
        aws_region=os.getenv("AWS_REGION", "eu-central-1"),
        endpoint_url=os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566"),
        access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
        secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
    )


def create_clients(config: Config) -> dict[str, Any]:
    session = boto3.session.Session()
    kwargs = {
        "endpoint_url": config.endpoint_url,
        "region_name": config.aws_region,
        "aws_access_key_id": config.access_key_id,
        "aws_secret_access_key": config.secret_access_key,
    }
    return {
        "sqs": session.client("sqs", **kwargs),
        "dynamodb": session.client("dynamodb", **kwargs),
        "secretsmanager": session.client("secretsmanager", **kwargs),
        "lambda": session.client("lambda", **kwargs),
    }


def wait_for_localstack(config: Config, timeout_seconds: int = 30) -> None:
    health_url = f"{config.endpoint_url.rstrip('/')}/_localstack/health"
    start = time.time()
    while (time.time() - start) <= timeout_seconds:
        try:
            with urlopen(health_url, timeout=2) as response:
                if response.status == 200:
                    return
        except (URLError, OSError):
            time.sleep(1)
            continue
        time.sleep(1)

    raise RuntimeError(
        f"LocalStack not ready after {timeout_seconds}s ({health_url}). "
        "Start LocalStack first with docker compose up -d."
    )


def ensure_queue(sqs_client: Any, queue_name: str) -> str:
    try:
        response = sqs_client.get_queue_url(QueueName=queue_name)
        return response["QueueUrl"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "AWS.SimpleQueueService.NonExistentQueue":
            raise
    response = sqs_client.create_queue(QueueName=queue_name)
    return response["QueueUrl"]


def get_queue_arn(sqs_client: Any, queue_url: str) -> str:
    response = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    return response["Attributes"]["QueueArn"]


def _mapping_summary(mapping: dict[str, Any]) -> str:
    uuid = mapping.get("UUID", "<unknown>")
    enabled = mapping.get("State") == "Enabled"
    batch_size = mapping.get("BatchSize")
    return f"uuid={uuid}, enabled={enabled}, batchSize={batch_size}"


def ensure_event_source_mapping(
    lambda_client: Any,
    sqs_client: Any,
    queue_name: str,
    function_name: str,
    batch_size: int,
) -> dict[str, Any]:
    queue_url = ensure_queue(sqs_client, queue_name)
    queue_arn = get_queue_arn(sqs_client, queue_url)

    try:
        lambda_client.get_function(FunctionName=function_name)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            raise RuntimeError(
                f"Required Lambda '{function_name}' does not exist. "
                "Deploy it before running LocalStack wiring bootstrap."
            ) from error
        raise

    response = lambda_client.list_event_source_mappings(
        FunctionName=function_name,
        EventSourceArn=queue_arn,
    )
    mappings = [m for m in response.get("EventSourceMappings", []) if m.get("State") != "Deleting"]

    if mappings:
        mapping = mappings[0]
        uuid = mapping["UUID"]
        needs_update = (
            mapping.get("BatchSize") != batch_size
            or mapping.get("State") != "Enabled"
        )
        if needs_update:
            mapping = lambda_client.update_event_source_mapping(
                UUID=uuid,
                BatchSize=batch_size,
                Enabled=True,
            )
        return mapping

    return lambda_client.create_event_source_mapping(
        FunctionName=function_name,
        EventSourceArn=queue_arn,
        BatchSize=batch_size,
        Enabled=True,
    )


def ensure_table(dynamodb_client: Any, table_name: str) -> None:
    try:
        dynamodb_client.describe_table(TableName=table_name)
        return
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

    dynamodb_client.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "eventId", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "eventId", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    waiter = dynamodb_client.get_waiter("table_exists")
    waiter.wait(TableName=table_name)


def upsert_secret(secrets_client: Any, name: str, secret_dict: dict[str, str]) -> None:
    secret_string = json.dumps(secret_dict)
    try:
        secrets_client.create_secret(Name=name, SecretString=secret_string)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "ResourceExistsException":
            raise
        secrets_client.put_secret_value(SecretId=name, SecretString=secret_string)


def bootstrap_resources(config: Config, clients: dict[str, Any]) -> None:
    print("Bootstrapping LocalStack resources...")

    print("- Ensuring SQS queues")
    for queue_name in QUEUE_NAMES:
        queue_url = ensure_queue(clients["sqs"], queue_name)
        print(f"  - {queue_name}: {queue_url}")

    print("- Ensuring DynamoDB tables")
    for table_name in TABLE_NAMES:
        ensure_table(clients["dynamodb"], table_name)
        print(f"  - {table_name}: ready")

    print("- Ensuring Secrets Manager secrets")
    for secret_name, payload in generate_secrets_payloads().items():
        upsert_secret(clients["secretsmanager"], secret_name, payload)
        print(f"  - {secret_name}: upserted")

    print("- Ensuring ingress SQS -> validation Lambda wiring")
    mapping = ensure_event_source_mapping(
        clients["lambda"],
        clients["sqs"],
        INGRESS_QUEUE_NAME,
        VALIDATION_FUNCTION_NAME,
        INGRESS_MAPPING_BATCH_SIZE,
    )
    print(f"  - {INGRESS_QUEUE_NAME} -> {VALIDATION_FUNCTION_NAME}: {_mapping_summary(mapping)}")

    print("- Ensuring accepted SQS -> persistence Lambda wiring")
    mapping = ensure_event_source_mapping(
        clients["lambda"],
        clients["sqs"],
        ACCEPTED_QUEUE_NAME,
        PERSISTENCE_FUNCTION_NAME,
        ACCEPTED_MAPPING_BATCH_SIZE,
    )
    print(f"  - {ACCEPTED_QUEUE_NAME} -> {PERSISTENCE_FUNCTION_NAME}: {_mapping_summary(mapping)}")

    print("- Ensuring rejected SQS -> audit Lambda wiring")
    mapping = ensure_event_source_mapping(
        clients["lambda"],
        clients["sqs"],
        REJECTED_QUEUE_NAME,
        AUDIT_FUNCTION_NAME,
        REJECTED_MAPPING_BATCH_SIZE,
    )
    print(f"  - {REJECTED_QUEUE_NAME} -> {AUDIT_FUNCTION_NAME}: {_mapping_summary(mapping)}")


def main() -> int:
    config = load_config()
    print(f"Using endpoint={config.endpoint_url}, region={config.aws_region}")
    wait_for_localstack(config)
    clients = create_clients(config)
    bootstrap_resources(config, clients)
    print("Bootstrap complete.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - CLI safeguard
        print(f"Bootstrap failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

