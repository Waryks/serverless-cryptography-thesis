package com.alexthesis.security.keys;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Optional TTL-based cache for parsed cryptographic keys.
 *
 * <p>Caching mode is determined by configuration:
 * <ul>
 *   <li>{@code 0} — no caching (baseline for worst-case measurements)</li>
 *   <li>{@code >0} — TTL-enabled cache (for realistic warm performance measurements)</li>
 * </ul>
 *
 * <p>Each key is cached independently by keyId+algorithm combination to avoid
 * stale entries when concurrent operations use different keys.
 */
public class KeyCache {

    private final long cacheTtlMs;
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    /**
     * Creates a KeyCache with the provided TTL in milliseconds.
     *
     * @param cacheTtlMs cache entry TTL in milliseconds; 0 disables caching
     */
    public KeyCache(long cacheTtlMs) {
        this.cacheTtlMs = cacheTtlMs;
    }

    /**
     * Retrieves a cached ParsedKey if present and not expired.
     * Automatically evicts expired entries.
     *
     * @param keyId the key identifier
     * @return an Optional containing the ParsedKey if cached and valid, empty otherwise
     */
    public Optional<ParsedKey> get(String keyId) {
        if (cacheTtlMs <= 0) {
            return Optional.empty();
        }

        CacheEntry entry = cache.get(keyId);
        if (entry == null) {
            return Optional.empty();
        }

        if (System.currentTimeMillis() < entry.expiryMs) {
            return Optional.of(entry.key);
        }

        cache.remove(keyId);
        return Optional.empty();
    }

    /**
     * Stores a ParsedKey in the cache if caching is enabled.
     *
     * @param keyId the key identifier
     * @param parsedKey the parsed key to cache
     */
    public void put(String keyId, ParsedKey parsedKey) {
        if (cacheTtlMs <= 0) {
            return;
        }

        long expiryMs = System.currentTimeMillis() + cacheTtlMs;
        cache.put(keyId, new CacheEntry(parsedKey, expiryMs));
    }

    /**
     * Invalidates a cached entry by keyId.
     * Called when a key is rotated or updated.
     *
     * @param keyId the key identifier to evict
     */
    public void invalidate(String keyId) {
        cache.remove(keyId);
    }

    /**
     * Clears all cached entries.
     * Called during key rotation stress tests or manual reset.
     */
    public void clear() {
        cache.clear();
    }

    /**
     * Returns the current cache size (for monitoring/debugging).
     */
    public int size() {
        return cache.size();
    }

    /**
     * Returns true if caching is enabled.
     */
    public boolean isEnabled() {
        return cacheTtlMs > 0;
    }

    /**
     * Immutable cache entry holding a parsed key and its absolute expiry timestamp.
     */
    private record CacheEntry(ParsedKey key, long expiryMs) {}
}




