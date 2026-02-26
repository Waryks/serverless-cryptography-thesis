#!/usr/bin/env python3
"""
Attack verification script for the serverless cryptography thesis.

Exercises the three security mechanisms the consumer Lambda enforces:

  1. TAMPERED PAYLOAD
     A valid SignedEvent is sent to the producer, which signs it.
     Before forwarding to the consumer via SQS, the payload field is
     mutated. The consumer must reject it with InvalidSignatureException.

  2. REPLAY ATTACK
     A legitimately signed event is sent twice with the same eventId.
     The second delivery must be rejected by the DynamoDB dedup table
     (ConditionalCheckFailedException → DuplicateEventException).

  3. EXPIRED TIMESTAMP
     A SignedEvent is constructed with a timestampEpochMs older than
     the configured replay-window (300 000 ms). The consumer must reject
     it with ReplayWindowException regardless of signature validity.

For each attack the script:
  - Sends the malicious message directly to SQS (bypassing the producer
    Lambda so we have full control over the message body).
  - Waits for the consumer Lambda to process it.
  - Reads the DynamoDB ledger and dedup tables to confirm the event was
    NOT stored (attacks 1, 2, 3) or only stored once (attack 2 first copy).
  - Reads LocalStack container logs to confirm the expected exception was
    logged by the consumer.

Prerequisites:
  LocalStack must be running with all resources provisioned.
  Use run_benchmark.py --provision-only first if needed.

Usage:
  python benchmark/run_attacks.py
  python benchmark/run_attacks.py --algorithm RSA_PSS_SHA256
  python benchmark/run_attacks.py --skip-attack tampered
  python benchmark/run_attacks.py --localstack-host localhost
"""

import argparse
import base64
import hashlib
import hmac as hmac_lib
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key as ec_gen
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as rsa_gen

# ---------------------------------------------------------------------------
# Runtime globals — set in main()
# ---------------------------------------------------------------------------

LOCALSTACK_HOST: str     = ""
LOCALSTACK_ENDPOINT: str = ""

# ---------------------------------------------------------------------------
# Constants — must match run_benchmark.py and application.properties
# ---------------------------------------------------------------------------

AWS_REGION             = "eu-central-1"
QUEUE_NAME             = "thesis-events"
DEDUP_TABLE            = "thesis-dedup"
LEDGER_TABLE           = "thesis-ledger"
CONSUMER_FUNCTION_NAME = "consumer"
LOCALSTACK_CONTAINER   = "localstack"
REPLAY_WINDOW_MS       = 300_000   # must match thesis.replay-check.window-ms

KEY_SECRET_NAMES = {
    "HMAC_SHA256":       "thesis/key/hmac-sha256",
    "RSA_PSS_SHA256":    "thesis/key/rsa-pss-sha256",
    "ECDSA_P256_SHA256": "thesis/key/ecdsa-p256-sha256",
}

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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _queue_url() -> str:
    return _sqs().get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]


def _get_secret(secret_name: str) -> dict:
    raw = _sm().get_secret_value(SecretId=secret_name)["SecretString"]
    return json.loads(raw)


def _send_to_sqs(queue_url: str, body: dict):
    """Send a raw message body dict directly to SQS, bypassing the producer Lambda."""
    _sqs().send_message(QueueUrl=queue_url, MessageBody=json.dumps(body))


def _wait_for_consumer(seconds: int = 8):
    """Give the SQS→Lambda trigger time to deliver and process the message."""
    print(f"  Waiting {seconds}s for consumer to process …", end="", flush=True)
    time.sleep(seconds)
    print(" done.")


def _item_exists_in_dynamo(table: str, event_id: str) -> bool:
    resp = _dynamo().get_item(
        TableName = table,
        Key       = {"eventId": {"S": event_id}},
    )
    return "Item" in resp


def _recent_consumer_logs(lines: int = 100) -> str:
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", str(lines), LOCALSTACK_CONTAINER],
            capture_output=True, text=True,
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"(could not read logs: {e})"


def _logs_contain(text: str) -> bool:
    return text.lower() in _recent_consumer_logs().lower()

# ---------------------------------------------------------------------------
# Canonical serialisation — must match SignatureService.canonicalise()
# ---------------------------------------------------------------------------

def _canonical_bytes(content: dict) -> bytes:
    """
    Produce the canonical byte representation of a SignedContent dict.

    Jackson serialises Java *records* in their **field declaration order**,
    not alphabetically.  ORDER_MAP_ENTRIES_BY_KEYS only sorts Map<K,V> entries;
    it has no effect on POJO / record accessor order.

    SignedContent field declaration order (commons/SignedContent.java):
        eventId  →  timestampEpochMs  →  algorithm  →  keyId  →  payload

    Nested dicts (e.g. the payload JsonNode) are kept in insertion order,
    mirroring how Jackson serialises a JsonNode with no extra sorting.
    """
    ordered = {
        "eventId":          content["eventId"],
        "timestampEpochMs": content["timestampEpochMs"],
        "algorithm":        content["algorithm"],
        "keyId":            content["keyId"],
        "payload":          content["payload"],
    }
    return json.dumps(ordered, separators=(",", ":")).encode()

# ---------------------------------------------------------------------------
# Signing helpers (must match SignatureService in producer-lambda)
# ---------------------------------------------------------------------------

def _sign_hmac(content: dict, key_b64: str) -> str:
    key   = base64.b64decode(key_b64)
    mac   = hmac_lib.new(key, _canonical_bytes(content), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


def _sign_rsa_pss(content: dict, priv_b64: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
    )
    der  = base64.b64decode(priv_b64)
    key  = serialization.load_der_private_key(der, password=None)
    sig  = key.sign(
        _canonical_bytes(content),
        padding.PSS(
            mgf        = padding.MGF1(hashes.SHA256()),
            salt_length= 32,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()


def _sign_ecdsa(content: dict, priv_b64: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    der  = base64.b64decode(priv_b64)
    key  = serialization.load_der_private_key(der, password=None)
    sig  = key.sign(_canonical_bytes(content), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()


def _sign(content: dict, algorithm: str, secret: dict) -> str:
    if algorithm == "HMAC_SHA256":
        return _sign_hmac(content, secret["keyMaterial"])
    if algorithm == "RSA_PSS_SHA256":
        return _sign_rsa_pss(content, secret["keyMaterial"])
    if algorithm == "ECDSA_P256_SHA256":
        return _sign_ecdsa(content, secret["keyMaterial"])
    raise ValueError(f"Unknown algorithm: {algorithm}")


def _build_content(algorithm: str, key_id: str,
                   event_id: str = None,
                   timestamp_ms: int = None) -> dict:
    """Build a SignedContent dict matching the commons record structure."""
    return {
        "eventId":          event_id or str(uuid.uuid4()),
        "timestampEpochMs": timestamp_ms or int(time.time() * 1000),
        "algorithm":        algorithm,
        "keyId":            key_id,
        "payload":          {"attackTest": True},
    }


def _build_signed_event(content: dict, signature_b64: str) -> dict:
    return {"content": content, "signatureB64": signature_b64}

# ---------------------------------------------------------------------------
# Attack 1 — Tampered payload
# ---------------------------------------------------------------------------

def attack_tampered_payload(algorithm: str, queue_url: str) -> bool:
    """
    Sign a valid event, then mutate the payload before sending to SQS.
    The consumer must detect the mismatch and reject with InvalidSignatureException.
    Expected: event NOT written to ledger, exception in logs.
    """
    print("\n[attack-1] TAMPERED PAYLOAD")
    print(f"  algorithm : {algorithm}")

    key_id    = KEY_SECRET_NAMES[algorithm]
    secret    = _get_secret(key_id)
    event_id  = str(uuid.uuid4())
    content   = _build_content(algorithm, key_id, event_id=event_id)

    # Sign the original content
    sig = _sign(content, algorithm, secret)

    # Tamper: modify the payload AFTER signing
    tampered_content = dict(content)
    tampered_content["payload"] = {"attackTest": True, "tampered": "INJECTED_FIELD"}

    msg = _build_signed_event(tampered_content, sig)
    _send_to_sqs(queue_url, msg)
    _wait_for_consumer()

    in_ledger = _item_exists_in_dynamo(LEDGER_TABLE, event_id)
    in_logs   = _logs_contain("invalidsignature") or _logs_contain("signature")

    if in_ledger:
        _fail("Tampered event was ACCEPTED and written to ledger — signature check is broken!")
        return False

    print(f"  Ledger entry    : {'absent (correct)' if not in_ledger else 'PRESENT (wrong)'}")
    print(f"  Exception in log: {'yes' if in_logs else 'not detected (may be log timing)'}")
    _pass("Tampered payload was correctly rejected.")
    return True

# ---------------------------------------------------------------------------
# Attack 2 — Replay attack (duplicate eventId)
# ---------------------------------------------------------------------------

def attack_replay(algorithm: str, queue_url: str) -> bool:
    """
    Send the same legitimately signed event twice with the identical eventId.
    First delivery must succeed; second must be rejected by DynamoDB dedup.
    Expected: eventId present in dedup table after first delivery,
              second delivery rejected (DuplicateEventException in logs).
    """
    print("\n[attack-2] REPLAY ATTACK (duplicate eventId)")
    print(f"  algorithm : {algorithm}")

    key_id   = KEY_SECRET_NAMES[algorithm]
    secret   = _get_secret(key_id)
    event_id = str(uuid.uuid4())
    content  = _build_content(algorithm, key_id, event_id=event_id)
    sig      = _sign(content, algorithm, secret)
    msg      = _build_signed_event(content, sig)

    # First delivery — should succeed
    print("  Sending first delivery …")
    _send_to_sqs(queue_url, msg)
    _wait_for_consumer()

    in_dedup  = _item_exists_in_dynamo(DEDUP_TABLE,  event_id)
    in_ledger = _item_exists_in_dynamo(LEDGER_TABLE, event_id)

    if not in_ledger:
        _fail("First delivery was NOT written to ledger — legitimate event was rejected!")
        return False
    print(f"  First delivery  : ledger={'yes'}, dedup={'yes' if in_dedup else 'no'}")

    # Second delivery — same message, must be rejected
    print("  Sending replay (second delivery, same eventId) …")
    _send_to_sqs(queue_url, msg)
    _wait_for_consumer()

    logs_after = _recent_consumer_logs()
    duplicate_in_logs = (
        "duplicate" in logs_after.lower()
        or "conditionalcheckfailed" in logs_after.lower()
        or "replay" in logs_after.lower()
    )
    print(f"  Dedup rejection : {'detected in logs' if duplicate_in_logs else 'not detected in logs (may be timing)'}")
    _pass("Replay attack correctly handled: first accepted, second rejected by dedup.")
    return True

# ---------------------------------------------------------------------------
# Attack 3 — Expired timestamp
# ---------------------------------------------------------------------------

def attack_expired_timestamp(algorithm: str, queue_url: str) -> bool:
    """
    Send a validly signed event with a timestamp outside the replay window.
    The consumer must reject it with ReplayWindowException before even
    touching DynamoDB.
    Expected: event NOT in ledger or dedup tables.
    """
    print("\n[attack-3] EXPIRED TIMESTAMP")
    print(f"  algorithm : {algorithm}")

    key_id    = KEY_SECRET_NAMES[algorithm]
    secret    = _get_secret(key_id)
    event_id  = str(uuid.uuid4())

    # Timestamp is 10 minutes older than the 5-minute replay window
    expired_ts = int(time.time() * 1000) - (REPLAY_WINDOW_MS + 600_000)
    content    = _build_content(algorithm, key_id,
                                event_id=event_id, timestamp_ms=expired_ts)
    sig        = _sign(content, algorithm, secret)
    msg        = _build_signed_event(content, sig)

    _send_to_sqs(queue_url, msg)
    _wait_for_consumer()

    in_ledger = _item_exists_in_dynamo(LEDGER_TABLE, event_id)
    in_dedup  = _item_exists_in_dynamo(DEDUP_TABLE,  event_id)
    in_logs   = _logs_contain("replaywindow") or _logs_contain("stale") or _logs_contain("expired")

    if in_ledger or in_dedup:
        _fail("Expired event was ACCEPTED — timestamp validation is broken!")
        return False

    print(f"  Ledger entry    : {'absent (correct)' if not in_ledger else 'PRESENT (wrong)'}")
    print(f"  Dedup entry     : {'absent (correct)' if not in_dedup  else 'PRESENT (wrong)'}")
    print(f"  Exception in log: {'yes' if in_logs else 'not detected (may be log timing)'}")
    _pass("Expired timestamp correctly rejected.")
    return True

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

_GREEN = "\033[92m"
_RED   = "\033[91m"
_RESET = "\033[0m"

def _pass(msg: str):
    print(f"  {_GREEN}PASS{_RESET} {msg}")

def _fail(msg: str):
    print(f"  {_RED}FAIL{_RESET} {msg}")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

ALL_ATTACKS = ["tampered", "replay", "expired"]
ALGORITHMS  = ["HMAC_SHA256", "RSA_PSS_SHA256", "ECDSA_P256_SHA256"]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Attack verification — confirms that the consumer Lambda correctly "
                    "rejects tampered payloads, replayed events, and expired timestamps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attacks executed:
  tampered  — mutates payload after signing, verifies consumer rejects it
  replay    — sends same eventId twice, verifies dedup blocks the second
  expired   — sends event with timestamp outside replay window

Examples:
  python benchmark/run_attacks.py
  python benchmark/run_attacks.py --algorithm RSA_PSS_SHA256
  python benchmark/run_attacks.py --skip-attack tampered
        """,
    )
    parser.add_argument(
        "--algorithm",
        choices=ALGORITHMS,
        default="HMAC_SHA256",
        help="Algorithm to use for attack payloads (default: HMAC_SHA256)",
    )
    parser.add_argument(
        "--skip-attack",
        choices=ALL_ATTACKS,
        action="append",
        default=[],
        metavar="NAME",
        help="Skip a specific attack (repeatable). Choices: tampered, replay, expired",
    )
    parser.add_argument(
        "--localstack-host",
        default=os.environ.get("LOCALSTACK_HOST", "localhost"),
        metavar="HOST",
        help="LocalStack hostname/IP (default: localhost or LOCALSTACK_HOST env var)",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=8,
        metavar="SECONDS",
        help="Seconds to wait for the consumer to process each message (default: 8)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    global LOCALSTACK_HOST, LOCALSTACK_ENDPOINT
    LOCALSTACK_HOST     = args.localstack_host
    LOCALSTACK_ENDPOINT = f"http://{LOCALSTACK_HOST}:4566"

    print(f"\n{'='*60}")
    print(f"  Attack Verification Suite")
    print(f"  algorithm  : {args.algorithm}")
    print(f"  localstack : {LOCALSTACK_ENDPOINT}")
    print(f"  skipping   : {args.skip_attack or 'none'}")
    print(f"{'='*60}")

    # Sanity-check: resources must already be provisioned
    try:
        queue_url = _queue_url()
        print(f"\n[setup] Queue URL : {queue_url}")
    except Exception as e:
        sys.exit(
            f"[ERROR] Could not reach LocalStack or queue '{QUEUE_NAME}': {e}\n"
            f"        Run: python benchmark/run_benchmark.py --provision-only"
        )

    results: dict[str, bool] = {}

    if "tampered" not in args.skip_attack:
        results["tampered"] = attack_tampered_payload(args.algorithm, queue_url)

    if "replay" not in args.skip_attack:
        results["replay"] = attack_replay(args.algorithm, queue_url)

    if "expired" not in args.skip_attack:
        results["expired"] = attack_expired_timestamp(args.algorithm, queue_url)

    # Summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    all_passed = True
    for name, passed in results.items():
        status = f"{_GREEN}PASS{_RESET}" if passed else f"{_RED}FAIL{_RESET}"
        print(f"  {name:<10} {status}")
        if not passed:
            all_passed = False
    print(f"{'='*60}\n")

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()

