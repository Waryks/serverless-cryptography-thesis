#!/usr/bin/env python3
"""Smoke-test LocalStack Story 1 resources."""

from __future__ import annotations

import json
import sys
from typing import Any

from botocore.exceptions import ClientError

import bootstrap


REQUIRED_SECRET_KEYS = {"keyId", "algorithm", "keyMaterial"}


def list_queue_names(sqs_client: Any) -> set[str]:
    queue_names: set[str] = set()
    next_token: str | None = None

    while True:
        kwargs = {}
        if next_token:
            kwargs["NextToken"] = next_token
        response = sqs_client.list_queues(**kwargs)

        for queue_url in response.get("QueueUrls", []):
            queue_names.add(queue_url.rstrip("/").split("/")[-1])

        next_token = response.get("NextToken")
        if not next_token:
            break

    return queue_names


def validate_secret(secrets_client: Any, secret_name: str) -> list[str]:
    errors: list[str] = []
    try:
        response = secrets_client.get_secret_value(SecretId=secret_name)
    except ClientError as error:
        return [f"secret missing: {secret_name} ({error.response.get('Error', {}).get('Code')})"]

    try:
        payload = json.loads(response["SecretString"])
    except (KeyError, json.JSONDecodeError):
        return [f"secret not valid JSON: {secret_name}"]

    missing_keys = REQUIRED_SECRET_KEYS - set(payload.keys())
    if missing_keys:
        errors.append(f"secret {secret_name} missing keys: {sorted(missing_keys)}")

    return errors


def validate_ingress_mapping(lambda_client: Any, sqs_client: Any) -> list[str]:
    failures: list[str] = []
    try:
        lambda_client.get_function(FunctionName=bootstrap.VALIDATION_FUNCTION_NAME)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        failures.append(
            f"validation lambda missing: {bootstrap.VALIDATION_FUNCTION_NAME} ({code})"
        )
        return failures

    try:
        queue_url = sqs_client.get_queue_url(QueueName=bootstrap.INGRESS_QUEUE_NAME)["QueueUrl"]
        queue_arn = sqs_client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["QueueArn"],
        )["Attributes"]["QueueArn"]
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        failures.append(f"ingress queue lookup failed: {bootstrap.INGRESS_QUEUE_NAME} ({code})")
        return failures

    response = lambda_client.list_event_source_mappings(
        FunctionName=bootstrap.VALIDATION_FUNCTION_NAME,
        EventSourceArn=queue_arn,
    )
    mappings = [m for m in response.get("EventSourceMappings", []) if m.get("State") != "Deleting"]
    if not mappings:
        failures.append(
            f"missing mapping: {bootstrap.INGRESS_QUEUE_NAME} -> {bootstrap.VALIDATION_FUNCTION_NAME}"
        )
        return failures

    mapping = mappings[0]
    if mapping.get("BatchSize") != bootstrap.INGRESS_MAPPING_BATCH_SIZE:
        failures.append(
            "mapping batch size mismatch: "
            f"expected={bootstrap.INGRESS_MAPPING_BATCH_SIZE} actual={mapping.get('BatchSize')}"
        )
    if mapping.get("State") != "Enabled":
        failures.append(f"mapping not enabled: state={mapping.get('State')}")

    return failures


def validate_accepted_mapping(lambda_client: Any, sqs_client: Any) -> list[str]:
    failures: list[str] = []
    try:
        lambda_client.get_function(FunctionName=bootstrap.PERSISTENCE_FUNCTION_NAME)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        failures.append(
            f"persistence lambda missing: {bootstrap.PERSISTENCE_FUNCTION_NAME} ({code})"
        )
        return failures

    try:
        queue_url = sqs_client.get_queue_url(QueueName=bootstrap.ACCEPTED_QUEUE_NAME)["QueueUrl"]
        queue_arn = sqs_client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["QueueArn"],
        )["Attributes"]["QueueArn"]
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        failures.append(f"accepted queue lookup failed: {bootstrap.ACCEPTED_QUEUE_NAME} ({code})")
        return failures

    response = lambda_client.list_event_source_mappings(
        FunctionName=bootstrap.PERSISTENCE_FUNCTION_NAME,
        EventSourceArn=queue_arn,
    )
    mappings = [m for m in response.get("EventSourceMappings", []) if m.get("State") != "Deleting"]
    if not mappings:
        failures.append(
            f"missing mapping: {bootstrap.ACCEPTED_QUEUE_NAME} -> {bootstrap.PERSISTENCE_FUNCTION_NAME}"
        )
        return failures

    mapping = mappings[0]
    if mapping.get("BatchSize") != bootstrap.ACCEPTED_MAPPING_BATCH_SIZE:
        failures.append(
            "mapping batch size mismatch: "
            f"expected={bootstrap.ACCEPTED_MAPPING_BATCH_SIZE} actual={mapping.get('BatchSize')}"
        )
    if mapping.get("State") != "Enabled":
        failures.append(f"mapping not enabled: state={mapping.get('State')}")

    return failures


def main() -> int:
    config = bootstrap.load_config()
    print(f"Running smoke test for endpoint={config.endpoint_url}, region={config.aws_region}")
    bootstrap.wait_for_localstack(config)
    clients = bootstrap.create_clients(config)

    failures: list[str] = []

    queue_names = list_queue_names(clients["sqs"])
    missing_queues = sorted(set(bootstrap.QUEUE_NAMES) - queue_names)
    if missing_queues:
        failures.append(f"missing queues: {missing_queues}")

    tables = clients["dynamodb"].list_tables().get("TableNames", [])
    missing_tables = sorted(set(bootstrap.TABLE_NAMES) - set(tables))
    if missing_tables:
        failures.append(f"missing tables: {missing_tables}")

    for secret_name in bootstrap.SECRET_NAMES:
        failures.extend(validate_secret(clients["secretsmanager"], secret_name))

    failures.extend(validate_ingress_mapping(clients["lambda"], clients["sqs"]))
    failures.extend(validate_accepted_mapping(clients["lambda"], clients["sqs"]))

    if failures:
        print("Smoke test failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Smoke test passed: queues, tables, secrets, and lambda wiring are present.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - CLI safeguard
        print(f"Smoke test failed unexpectedly: {exc}", file=sys.stderr)
        raise SystemExit(1)

