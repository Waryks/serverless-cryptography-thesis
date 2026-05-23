from __future__ import annotations

from pathlib import Path
from typing import List

from benchmark.output.csv_writer import write_csv
from benchmark.output.json_writer import write_json


def write_summary_csv(path: Path, rows: List[dict]) -> None:
    write_csv(path, rows)


def write_summary_json(path: Path, payload: dict) -> None:
    write_json(path, payload)

