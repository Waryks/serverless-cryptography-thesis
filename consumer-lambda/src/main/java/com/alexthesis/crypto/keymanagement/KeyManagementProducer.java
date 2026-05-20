package com.alexthesis.crypto.keymanagement;

import com.alexthesis.security.keys.KeyCache;
import com.alexthesis.security.keys.KeyProvider;
import com.alexthesis.security.keys.KeyResolver;
import com.alexthesis.security.keys.RotationPolicy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Quarkus bean producer for the key management subsystem in the Consumer Lambda.
 *
 * <p>Creates and configures:
 * <ul>
 *   <li>KeyCache — optional TTL-based caching of parsed keys</li>
 *   <li>RotationPolicy — key rotation behavior (strict vs relaxed)</li>
 *   <li>KeyResolver — orchestrates key resolution with the key management subsystem</li>
 * </ul>
 *
 * <p>Configuration properties:
 * <ul>
 *   <li>{@code thesis.security.key-cache-ttl-ms} — cache TTL in milliseconds (0 = disabled)</li>
 *   <li>{@code thesis.security.allow-previous-key} — allow fallback verification with previous key</li>
 *   <li>{@code thesis.security.grace-period-ms} — grace period for previous key acceptance</li>
 * </ul>
 */
@ApplicationScoped
public class KeyManagementProducer {

    private final KeyCache keyCache;
    private final RotationPolicy rotationPolicy;
    private final KeyProvider keyProvider;

    @Inject
    public KeyManagementProducer(
            KeyProvider keyProvider,
            @ConfigProperty(name = "thesis.security.key-cache-ttl-ms", defaultValue = "0") long cacheTtlMs,
            @ConfigProperty(name = "thesis.security.allow-previous-key", defaultValue = "false") boolean allowPreviousKey,
            @ConfigProperty(name = "thesis.security.grace-period-ms", defaultValue = "300000") long gracePeriodMs) {
        this.keyProvider = keyProvider;
        this.keyCache = new KeyCache(cacheTtlMs);
        this.rotationPolicy = allowPreviousKey ?
                RotationPolicy.relaxed(gracePeriodMs) :
                RotationPolicy.strict();
    }

    /** Produces the configured KeyCache bean. */
    @Produces
    @ApplicationScoped
    public KeyCache produceKeyCache() {
        return keyCache;
    }

    /** Produces the configured RotationPolicy bean. */
    @Produces
    @ApplicationScoped
    public RotationPolicy produceRotationPolicy() {
        return rotationPolicy;
    }

    /** Produces the KeyResolver bean that orchestrates key resolution. */
    @Produces
    @ApplicationScoped
    public KeyResolver produceKeyResolver() {
        return new KeyResolver(keyProvider, keyCache, rotationPolicy);
    }
}

