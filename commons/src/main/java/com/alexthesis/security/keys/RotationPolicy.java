package com.alexthesis.security.keys;

/**
 * Defines rotation-aware verification policies for cryptographic operations.
 *
 * <p>Supports graceful key rotation by allowing verification to fall back to a previous key
 * if the current key fails and policy permits previous-key verification.
 *
 * <p>Example:
 * <pre>
 *   1. Try verification with current key
 *   2. If verification fails:
 *      - Check whether policy allows previous key
 *   3. Try verification with previous key
 *   4. If previous succeeds:
 *      - Accept during grace period
 *   5. Otherwise reject
 * </pre>
 */
public record RotationPolicy(
        boolean allowPreviousKeyVerification,
        long gracePeriodMs
) {

    /**
     * Creates a strict rotation policy that does not allow previous-key verification.
     * Used when all events must use the current key.
     */
    public static RotationPolicy strict() {
        return new RotationPolicy(false, 0);
    }

    /**
     * Creates a relaxed rotation policy that allows previous-key verification during a grace period.
     *
     * @param gracePeriodMs the grace period in milliseconds during which previous-key verification
     *                      is allowed after a key rotation event
     */
    public static RotationPolicy relaxed(long gracePeriodMs) {
        return new RotationPolicy(true, gracePeriodMs);
    }

    /**
     * Returns true if previous-key verification is permitted.
     */
    public boolean allowsPreviousKey() {
        return allowPreviousKeyVerification;
    }

    /**
     * Returns the grace period in milliseconds.
     */
    public long getGracePeriodMs() {
        return gracePeriodMs;
    }

    /**
     * Checks if we are still within the grace period for previous-key acceptance.
     *
     * @param keyRotationEpochMs the timestamp when the key was rotated
     * @return true if we are still within the grace period, false otherwise
     */
    public boolean isWithinGracePeriod(long keyRotationEpochMs) {
        if (!allowPreviousKeyVerification) {
            return false;
        }
        long age = System.currentTimeMillis() - keyRotationEpochMs;
        return age <= gracePeriodMs;
    }

    /**
     * Creates a default policy suitable for testing and benchmarking.
     * Allows previous key with a 5-minute grace period.
     */
    public static RotationPolicy defaultPolicy() {
        return relaxed(5 * 60 * 1000); // 5 minutes
    }
}

