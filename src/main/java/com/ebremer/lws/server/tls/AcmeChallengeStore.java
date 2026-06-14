package com.ebremer.lws.server.tls;

import java.util.concurrent.TimeUnit;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Holds the in-flight ACME HTTP-01 challenge tokens (token &rarr; key authorization) that
 * {@link AcmeCertificateManager} publishes while validating a domain and {@link AcmeChallengeServlet}
 * serves over HTTP. Entries are normally removed explicitly once a challenge completes; a short TTL
 * and a size bound are a defensive backstop so a token can never leak indefinitely if a flow is
 * interrupted before its {@code remove}.
 *
 * @author Erich Bremer
 */
public final class AcmeChallengeStore {

    private final Cache<String, String> tokens = Caffeine.newBuilder()
            .expireAfterWrite(15, TimeUnit.MINUTES)
            .maximumSize(1_000)
            .build();

    public void put(String token, String keyAuthorization) {
        tokens.put(token, keyAuthorization);
    }

    /** The key authorization to return for an HTTP-01 token, or {@code null} if unknown. */
    public String get(String token) {
        return tokens.getIfPresent(token);
    }

    public void remove(String token) {
        tokens.invalidate(token);
    }
}
