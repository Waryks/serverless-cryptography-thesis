from __future__ import annotations

import random
import string
import uuid


def random_uuid() -> str:
    return str(uuid.uuid4())


def random_string(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def random_float() -> float:
    return round(random.uniform(0.0, 10000.0), 4)


def random_int() -> int:
    return random.randint(0, 10_000_000)
