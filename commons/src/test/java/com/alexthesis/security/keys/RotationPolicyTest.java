package com.alexthesis.security.keys;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RotationPolicyTest {

    @Test
    void strict_DoesNotAllowPreviousKeyVerification() {
        // Act
        RotationPolicy policy = RotationPolicy.strict();

        // Assert
        assertFalse(policy.allowsPreviousKey());
        assertEquals(0, policy.getGracePeriodMs());
    }

    @Test
    void relaxed_AllowsPreviousKeyVerification() {
        // Act
        RotationPolicy policy = RotationPolicy.relaxed(5 * 60 * 1000);

        // Assert
        assertTrue(policy.allowsPreviousKey());
        assertEquals(5 * 60 * 1000, policy.getGracePeriodMs());
    }

    @Test
    void defaultPolicy_AllowsPreviousKey() {
        // Act
        RotationPolicy policy = RotationPolicy.defaultPolicy();

        // Assert
        assertTrue(policy.allowsPreviousKey());
    }

    @Test
    void isWithinGracePeriod_ReturnsFalse_WhenPolicyDoesNotAllowPreviousKey() {
        // Arrange
        RotationPolicy policy = RotationPolicy.strict();
        long rotationTime = System.currentTimeMillis();

        // Act
        boolean result = policy.isWithinGracePeriod(rotationTime);

        // Assert
        assertFalse(result);
    }

    @Test
    void isWithinGracePeriod_ReturnsTrue_WhenWithinGracePeriod() throws InterruptedException {
        // Arrange
        long gracePeriodMs = 1000; // 1 second
        RotationPolicy policy = RotationPolicy.relaxed(gracePeriodMs);
        long rotationTime = System.currentTimeMillis() - 500; // 500ms ago

        // Act
        boolean result = policy.isWithinGracePeriod(rotationTime);

        // Assert
        assertTrue(result);
    }

    @Test
    void isWithinGracePeriod_ReturnsFalse_WhenOutsideGracePeriod() throws InterruptedException {
        // Arrange
        long gracePeriodMs = 100; // 100ms
        RotationPolicy policy = RotationPolicy.relaxed(gracePeriodMs);
        long rotationTime = System.currentTimeMillis() - 200; // 200ms ago (outside grace period)

        // Wait a bit to ensure we're definitely outside
        Thread.sleep(50);

        // Act
        boolean result = policy.isWithinGracePeriod(rotationTime);

        // Assert
        assertFalse(result);
    }
}

