package com.alexthesis.metrics;

/**
 * Pluggable recorder for timing snapshots. Lambdas may implement this to export
 * snapshots to logs, message attributes, or external systems.
 */
public interface MetricsRecorder {
    void record(TimingSnapshot snapshot);
}

