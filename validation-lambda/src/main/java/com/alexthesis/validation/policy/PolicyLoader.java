package com.alexthesis.validation.policy;

import com.alexthesis.messaging.Algorithm;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Loads {@link SecurityPolicy} definitions from MicroProfile configuration.
 *
 * <p>Policies are configured under the prefix:
 * <pre>
 * thesis.policy.&lt;policyId&gt;.*
 * </pre>
 */
@ApplicationScoped
public class PolicyLoader {

    private static final long DEFAULT_REPLAY_WINDOW_MS = 300_000L;

    private final Config config;
    private final ConcurrentHashMap<String, SecurityPolicy> cache = new ConcurrentHashMap<>();

    @Inject
    public PolicyLoader(Config config) {
        this.config = config;
    }

    public SecurityPolicy loadPolicy(String policyId) {
        return cache.computeIfAbsent(policyId, this::readPolicy);
    }

    private SecurityPolicy readPolicy(String policyId) {
        String prefix = "thesis.policy." + policyId + ".";
        Algorithm allowedAlgorithm = Algorithm.valueOf(requiredValue(prefix + "algorithm", String.class));
        boolean replayCheckEnabled = optionalValue(prefix + "replay-enabled", Boolean.class, true);
        long replayWindowMs = optionalValue(prefix + "replay-window-ms", Long.class, DEFAULT_REPLAY_WINDOW_MS);
        boolean dedupEnabled = optionalValue(prefix + "dedup-enabled", Boolean.class, true);
        boolean allowPreviousKey = optionalValue(prefix + "allow-previous-key", Boolean.class, false);
        boolean strictValidation = optionalValue(prefix + "strict-validation", Boolean.class, true);

        return new SecurityPolicy(
                policyId,
                allowedAlgorithm,
                replayCheckEnabled,
                replayWindowMs,
                dedupEnabled,
                allowPreviousKey,
                strictValidation
        );
    }

    private <T> T requiredValue(String key, Class<T> type) {
        return config.getOptionalValue(key, type)
                .orElseThrow(() -> new IllegalStateException("Missing policy configuration: " + key));
    }

    private <T> T optionalValue(String key, Class<T> type, T defaultValue) {
        return config.getOptionalValue(key, type).orElse(defaultValue);
    }
}

