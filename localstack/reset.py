#!/usr/bin/env python3
"""Reset LocalStack resources for Story 1 and recreate them."""

from __future__ import annotations

import sys
from typing import Any

from botocore.exceptions import ClientError

import bootstrap


def delete_queue_if_exists(sqs_client: Any, queue_name: str) -> None:
    try:
        queue_url = sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "AWS.SimpleQueueService.NonExistentQueue":
            return
        raise
    sqs_client.delete_queue(QueueUrl=queue_url)


def delete_table_if_exists(dynamodb_client: Any, table_name: str) -> None:
    try:
        dynamodb_client.delete_table(TableName=table_name)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise


def delete_secret_if_exists(secrets_client: Any, secret_name: str) -> None:
    try:
        secrets_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise


def delete_ingress_mappings_if_exists(lambda_client: Any, sqs_client: Any) -> None:
    try:
        queue_url = sqs_client.get_queue_url(QueueName=bootstrap.INGRESS_QUEUE_NAME)["QueueUrl"]
        queue_arn = sqs_client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["QueueArn"],
        )["Attributes"]["QueueArn"]
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code == "AWS.SimpleQueueService.NonExistentQueue":
            return
        raise

    try:
        response = lambda_client.list_event_source_mappings(
            FunctionName=bootstrap.VALIDATION_FUNCTION_NAME,
            EventSourceArn=queue_arn,
        )
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        raise

    for mapping in response.get("EventSourceMappings", []):
        uuid = mapping.get("UUID")
        if uuid:
            lambda_client.delete_event_source_mapping(UUID=uuid)


def main() -> int:
    config = bootstrap.load_config()
    print(f"Using endpoint={config.endpoint_url}, region={config.aws_region}")
    bootstrap.wait_for_localstack(config)
    clients = bootstrap.create_clients(config)

    print("Resetting LocalStack resources...")

    print("- Deleting ingress mapping")
    delete_ingress_mappings_if_exists(clients["lambda"], clients["sqs"])
    print(f"  - {bootstrap.INGRESS_QUEUE_NAME} -> {bootstrap.VALIDATION_FUNCTION_NAME}: deleted or absent")

    print("- Deleting SQS queues")
    for queue_name in bootstrap.QUEUE_NAMES:
        delete_queue_if_exists(clients["sqs"], queue_name)
        print(f"  - {queue_name}: deleted or absent")

    print("- Deleting DynamoDB tables")
    for table_name in bootstrap.TABLE_NAMES:
        delete_table_if_exists(clients["dynamodb"], table_name)
        print(f"  - {table_name}: deleted or absent")

    print("- Deleting Secrets Manager secrets")
    for secret_name in bootstrap.SECRET_NAMES:
        delete_secret_if_exists(clients["secretsmanager"], secret_name)
        print(f"  - {secret_name}: deleted or absent")

    # Recreate baseline immediately so every run starts from the same state.
    bootstrap.bootstrap_resources(config, clients)
    print("Reset complete.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - CLI safeguard
        print(f"Reset failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

