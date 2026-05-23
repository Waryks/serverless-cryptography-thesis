from __future__ import annotations

from benchmark.metrics.statistics import summarize_latency, summarize_outcomes


def build_metrics(rows: list[dict]) -> dict:
    producer_latencies = [
        float(row["producer_latency_ms"])
        for row in rows
        if row.get("producer_latency_ms") is not None
    ]
    e2e_latencies = [
        float(row["end_to_end_latency_ms"])
        for row in rows
        if row.get("end_to_end_latency_ms") is not None
    ]

    return {
        "producer_latency_ms": summarize_latency(producer_latencies),
        "end_to_end_latency_ms": summarize_latency(e2e_latencies),
        "outcomes": summarize_outcomes(rows),
    }

