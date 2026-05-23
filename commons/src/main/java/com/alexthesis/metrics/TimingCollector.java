package com.alexthesis.metrics;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory collector for timings. Designed to be lightweight and per-JVM.
 */
public class TimingCollector {
    private static final TimingCollector INSTANCE = new TimingCollector();

    // eventId -> context
    private final ConcurrentHashMap<String, Context> contexts = new ConcurrentHashMap<>();

    public static TimingCollector get() {
        return INSTANCE;
    }

    public void start(String eventId, TimingStage stage) {
        Context ctx = contexts.computeIfAbsent(eventId, k -> new Context());
        ctx.start(stage);
    }

    public void stop(String eventId, TimingStage stage) {
        Context ctx = contexts.get(eventId);
        if (ctx != null) {
            ctx.stop(stage);
        }
    }

    public Optional<TimingSnapshot> snapshot(String eventId, String serviceName, boolean coldStart) {
        Context ctx = contexts.get(eventId);
        if (ctx == null) return Optional.empty();

        Map<String, Double> durationsMs = new HashMap<>();
        long startMs = ctx.startEpochMs == 0 ? 0 : ctx.startEpochMs;
        long endMs = ctx.endEpochMs == 0 ? 0 : ctx.endEpochMs;

        for (Map.Entry<TimingStage, Long> e : ctx.durationsNanos.entrySet()) {
            double ms = e.getValue() / 1_000_000.0;
            durationsMs.put(e.getKey().name(), ms);
        }

        TimingSnapshot snapshot = new TimingSnapshot(eventId, serviceName, coldStart, durationsMs, startMs, endMs);
        return Optional.of(snapshot);
    }

    public void remove(String eventId) {
        contexts.remove(eventId);
    }

    private static class Context {
        // stage -> startNano
        private final Map<TimingStage, Long> starts = new HashMap<>();
        // stage -> durationNanos
        private final Map<TimingStage, Long> durationsNanos = new HashMap<>();
        private long startEpochMs;
        private long endEpochMs;

        synchronized void start(TimingStage stage) {
            long now = System.nanoTime();
            if (starts.isEmpty()) {
                startEpochMs = Instant.now().toEpochMilli();
            }
            starts.put(stage, now);
        }

        synchronized void stop(TimingStage stage) {
            Long s = starts.remove(stage);
            long now = System.nanoTime();
            if (s != null) {
                long duration = now - s;
                durationsNanos.put(stage, duration + durationsNanos.getOrDefault(stage, 0L));
            }
            endEpochMs = Instant.now().toEpochMilli();
        }
    }
}

