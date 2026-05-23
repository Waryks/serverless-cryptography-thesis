from __future__ import annotations

from benchmark.metrics.percentile_metrics import percentile


def summarize_latency(values: list[float]) -> dict:
    if not values:
        return {
            "count": 0,
            "min": None,
            "max": None,
            "average": None,
            "p50": None,
            "p95": None,
            "p99": None,
        }

    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "average": sum(values) / len(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
    }


def summarize_outcomes(rows: list[dict]) -> dict:
    total = len(rows)
    successes = sum(1 for row in rows if row.get("matched_expected_outcome"))
    rejected = sum(1 for row in rows if row.get("final_outcome") == "REJECTED")

    if total == 0:
        return {
            "total": 0,
            "success_rate": 0.0,
            "rejection_rate": 0.0,
        }

    return {
        "total": total,
        "success_rate": successes / total,
        "rejection_rate": rejected / total,
    }

