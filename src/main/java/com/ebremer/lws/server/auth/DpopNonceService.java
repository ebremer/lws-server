package com.ebremer.lws.server.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Issues and validates DPoP server nonces (RFC 9449 §8). Nonces are <em>stateless</em>: each is a
 * timestamp plus an HMAC of that timestamp under a per-process secret, so validity is checked by
 * recomputing the HMAC and confirming the timestamp is within the acceptance window — no
 * server-side nonce store to maintain or purge.
 *
 * @author Erich Bremer
 */
public final class DpopNonceService {

    private final byte[] secret = new byte[32];
    private final long ttlMs;
    private final long skewMs;

    public DpopNonceService() {
        this(300_000L, 60_000L);
    }

    public DpopNonceService(long ttlMs, long skewMs) {
        this.ttlMs = ttlMs;
        this.skewMs = skewMs;
        new SecureRandom().nextBytes(secret);
    }

    /** Mint a fresh nonce for a {@code DPoP-Nonce} challenge. */
    public String issue() {
        String payload = Long.toString(System.currentTimeMillis());
        return encode(payload.getBytes(StandardCharsets.US_ASCII)) + "." + encode(hmac(payload));
    }

    /** True if {@code nonce} was issued by this service and is still within its acceptance window. */
    public boolean isValid(String nonce) {
        if (nonce == null) {
            return false;
        }
        int dot = nonce.indexOf('.');
        if (dot <= 0 || dot == nonce.length() - 1) {
            return false;
        }
        try {
            String payload = new String(decode(nonce.substring(0, dot)), StandardCharsets.US_ASCII);
            byte[] mac = decode(nonce.substring(dot + 1));
            if (!MessageDigest.isEqual(mac, hmac(payload))) {
                return false;
            }
            long issued = Long.parseLong(payload);
            long now = System.currentTimeMillis();
            return issued <= now + skewMs && issued >= now - ttlMs;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private byte[] hmac(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(payload.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] decode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }
}
