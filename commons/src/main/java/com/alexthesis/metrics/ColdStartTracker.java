package com.alexthesis.metrics;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks whether a service is experiencing its first invocation in the current JVM (cold start).
 */
public class ColdStartTracker {
    private static final Set<String> seen = ConcurrentHashMap.newKeySet();

    /**
     * Returns true if this is the first observed invocation for serviceName and marks it as seen.
     */
    public static boolean isColdStartAndMark(String serviceName) {
        return seen.add(serviceName);
    }
}

