package com.ebremer.lws.server.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies DPoP (Demonstrating Proof-of-Possession) proofs per
 * <a href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449</a>. A DPoP-bound request carries the
 * access token in {@code Authorization: DPoP <token>} and a proof JWT in the {@code DPoP} header.
 *
 * <p>{@link #verifyProof} checks the proof JWT: {@code typ=dpop+jwt}, a real (non-{@code none})
 * algorithm, a signature made by the public key embedded in its {@code jwk} header, the
 * {@code htm}/{@code htu} of the request, {@code iat} freshness, {@code jti} uniqueness (replay
 * protection), and {@code ath} (the SHA-256 of the access token, binding the proof to it). On
 * success it returns the JWK SHA-256 thumbprint ({@code jkt}) of the proof key, which must equal
 * the access token's {@code cnf.jkt} (see {@link #isBoundTo}).
 *
 * @author Erich Bremer
 */
public final class DpopValidator {

    private static final Logger log = LoggerFactory.getLogger(DpopValidator.class);

    private static final String DPOP_JWT_TYPE = "dpop+jwt";

    /** Default upper bound on retained {@code jti} entries; bounds memory under high request volume. */
    public static final long DEFAULT_MAX_JTI = 100_000L;

    /** At most one eviction warning per this interval, so the log cannot become the denial of service. */
    private static final long EVICTION_LOG_INTERVAL_NANOS = TimeUnit.MINUTES.toNanos(1);

    private final long maxAgeMs;
    private final long skewMs;
    private final long maxJti;
    private final DpopNonceService nonceService; // null => nonces not required
    // Replay guard: a bounded, TTL-evicting cache of seen jti (entries expire after the acceptance window).
    private final Cache<String, Boolean> seenJti;
    private final java.util.concurrent.atomic.AtomicLong sizeEvictions =
            new java.util.concurrent.atomic.AtomicLong();
    private volatile long lastEvictionLogAt;

    public DpopValidator() {
        this(300_000L, 60_000L, null, DEFAULT_MAX_JTI);
    }

    public DpopValidator(DpopNonceService nonceService) {
        this(300_000L, 60_000L, nonceService, DEFAULT_MAX_JTI);
    }

    public DpopValidator(DpopNonceService nonceService, long maxJti) {
        this(300_000L, 60_000L, nonceService, maxJti);
    }

    public DpopValidator(long maxAgeMs, long skewMs, DpopNonceService nonceService) {
        this(maxAgeMs, skewMs, nonceService, DEFAULT_MAX_JTI);
    }

    public DpopValidator(long maxAgeMs, long skewMs, DpopNonceService nonceService, long maxJti) {
        this.maxAgeMs = maxAgeMs;
        this.skewMs = skewMs;
        this.nonceService = nonceService;
        this.maxJti = maxJti;
        this.seenJti = Caffeine.newBuilder()
                // The acceptance window, not maxAgeMs. A proof is accepted while its iat lies in
                // [now - maxAgeMs, now + skewMs], so it stays usable for maxAgeMs + skewMs from the
                // moment it was minted. Expiring the jti after maxAgeMs left a proof issued up to
                // skewMs in the future replayable for that last skewMs, because its entry was gone
                // while the proof itself was still fresh enough to accept.
                .expireAfterWrite(replayWindowMs(maxAgeMs, skewMs), TimeUnit.MILLISECONDS)
                .maximumSize(maxJti)
                // An entry evicted for SIZE has not expired, so the proof that created it is inside
                // its acceptance window and is replayable again from this moment on. That is the one
                // condition under which the replay guard is not doing its job, and nothing else
                // surfaces it: the request that suffers is somebody else's, later, and it succeeds.
                // evictionListener, not removalListener: the former runs synchronously as part of
                // the eviction, so the count is accurate the moment the entry is gone.
                .evictionListener((String jti, Boolean seen, com.github.benmanes.caffeine.cache.RemovalCause cause) -> {
                    if (cause == com.github.benmanes.caffeine.cache.RemovalCause.SIZE) {
                        reportSizeEviction();
                    }
                })
                .build();
    }

    /**
     * Count a size eviction and say so at most once a minute, with the running total.
     *
     * <p>Rate-limited because the condition that produces one produces a great many: the cache is
     * full and every further proof evicts an unexpired entry. An unthrottled line per eviction would
     * turn a capacity problem into a second, larger one.
     */
    private void reportSizeEviction() {
        long total = sizeEvictions.incrementAndGet();
        long now = System.nanoTime();
        if (now - lastEvictionLogAt < EVICTION_LOG_INTERVAL_NANOS) {
            return;
        }
        lastEvictionLogAt = now;
        log.warn("The DPoP replay cache is full ({} entries) and is evicting proofs that have not yet "
                + "expired: {} so far. Those proofs are replayable again within their {}ms acceptance "
                + "window. Raise lws.dpop.jti-cache-size above the number of DPoP requests expected in "
                + "that window.", maxJti, total, replayWindowMs());
    }

    /** How many unexpired {@code jti} entries have been evicted for size (a replay window reopening). */
    public long sizeEvictions() {
        return sizeEvictions.get();
    }

    /**
     * How long a proof stays acceptable, and therefore how long its {@code jti} must be remembered:
     * the full {@code iat} window, from the earliest issue time still accepted to the latest.
     */
    static long replayWindowMs(long maxAgeMs, long skewMs) {
        return maxAgeMs + skewMs;
    }

    /** This validator's replay window, for tests and for the eviction warning. */
    long replayWindowMs() {
        return replayWindowMs(maxAgeMs, skewMs);
    }

    /** True if this server requires a {@code nonce} claim in DPoP proofs (RFC 9449 §8). */
    public boolean nonceRequired() {
        return nonceService != null;
    }

    /** Mint a fresh nonce for a {@code DPoP-Nonce} challenge, or {@code null} if nonces are off. */
    public String issueNonce() {
        return nonceService == null ? null : nonceService.issue();
    }

    /** True if the proof carries a valid server-issued {@code nonce} (or nonces are not required). */
    public boolean isNonceValid(String proof) {
        if (nonceService == null) {
            return true;
        }
        try {
            String nonce = SignedJWT.parse(proof).getJWTClaimsSet().getStringClaim("nonce");
            return nonce != null && nonceService.isValid(nonce);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verify a DPoP proof for a request to {@code htm htu} that presents {@code accessToken}.
     *
     * <p>This does <em>not</em> consume the proof's {@code jti}: replay protection is claimed
     * separately, through {@link #claimProof}, once the caller has validated the access token. See
     * that method for why the two are apart (finding M6).
     *
     * @return the proof key's JWK thumbprint if valid, otherwise empty
     */
    public Optional<String> verifyProof(String htm, String htu, String proof, String accessToken) {
        try {
            SignedJWT jwt = SignedJWT.parse(proof);
            JWSHeader header = jwt.getHeader();

            if (header.getType() == null || !DPOP_JWT_TYPE.equals(header.getType().getType())) {
                return Optional.empty();
            }
            if (!JwsSupport.algNotNone(jwt)) {
                return Optional.empty();
            }
            JWK jwk = header.getJWK();
            if (jwk == null || jwk.isPrivate()) {
                return Optional.empty(); // proof must embed a public key only
            }
            if (!JwsSupport.verify(jwt, jwk)) {
                return Optional.empty();
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (!htm.equalsIgnoreCase(claims.getStringClaim("htm"))) {
                return Optional.empty();
            }
            if (!htuMatches(htu, claims.getStringClaim("htu"))) {
                return Optional.empty();
            }
            Date iat = claims.getIssueTime();
            long now = System.currentTimeMillis();
            if (iat == null || iat.getTime() > now + skewMs || iat.getTime() < now - maxAgeMs) {
                return Optional.empty();
            }
            if (claims.getJWTID() == null) {
                return Optional.empty(); // a proof with no jti cannot be replay-protected
            }
            String ath = claims.getStringClaim("ath");
            if (ath == null || !ath.equals(sha256Base64Url(accessToken))) {
                return Optional.empty(); // proof not bound to this access token
            }
            return Optional.of(jwk.computeThumbprint().toString());
        } catch (Exception e) {
            log.debug("DPoP proof verification failed: {}", e.toString());
            return Optional.empty();
        }
    }

    /**
     * True if {@code accessToken} is sender-constrained — that is, it carries a {@code cnf.jkt}
     * confirmation claim binding it to a holder key.
     *
     * <p>RFC 9449 §7.1 requires a resource server to <strong>reject</strong> such a token when it
     * arrives under the {@code Bearer} scheme: the whole value of the binding is that possession of
     * the token alone is not sufficient, so honouring it without a proof would let anyone who
     * captured it (from a proxy log, an APM trace, a referrer) use it as if they held the key.
     *
     * <p>Returns {@code false} for anything that is not a parseable JWT (e.g. a SAML assertion).
     */
    public static boolean isSenderConstrained(String accessToken) {
        try {
            Map<String, Object> cnf = SignedJWT.parse(accessToken).getJWTClaimsSet().getJSONObjectClaim("cnf");
            return cnf != null && cnf.get("jkt") != null;
        } catch (Exception e) {
            return false;
        }
    }

    /** True if {@code accessToken} (a JWT) is bound to the key with thumbprint {@code jkt} via {@code cnf.jkt}. */
    public static boolean isBoundTo(String accessToken, String jkt) {
        try {
            SignedJWT jwt = SignedJWT.parse(accessToken);
            Map<String, Object> cnf = jwt.getJWTClaimsSet().getJSONObjectClaim("cnf");
            return cnf != null && jkt.equals(cnf.get("jkt"));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean htuMatches(String expected, String proofHtu) {
        if (proofHtu == null) {
            return false;
        }
        return stripQueryAndFragment(expected).equals(stripQueryAndFragment(proofHtu));
    }

    private static String stripQueryAndFragment(String uri) {
        int cut = uri.length();
        int q = uri.indexOf('?');
        if (q >= 0) {
            cut = q;
        }
        int f = uri.indexOf('#');
        if (f >= 0 && f < cut) {
            cut = f;
        }
        return uri.substring(0, cut);
    }

    /**
     * Claim a verified proof's {@code jti}, returning {@code false} if it was already claimed within
     * the acceptance window — that is, this is a replay.
     *
     * <p><b>Call this last, once the access token the proof is bound to has itself been validated
     * (finding M6).</b> It used to run inside {@link #verifyProof}, before the {@code ath} check and
     * long before anything looked at the access token, so every check standing in front of it was one
     * an attacker could satisfy alone: the proof embeds its own verification key, so it is self-signed
     * by construction, and {@code ath} only has to match whatever string is sent as the access token.
     * An unauthenticated client could therefore write one entry per request into a cache capped at
     * {@code maxJti} with a {@code maxAgeMs} window — a few hundred requests a second, sustained, and
     * the cache starts evicting entries that have not expired, which re-enables the very replay it
     * exists to stop. Claiming the {@code jti} only for a request that presented a valid, bound access
     * token means filling the cache now costs what a real request costs.
     *
     * <p>The check and the record stay one atomic {@code putIfAbsent}, so two concurrent replays of
     * the same proof cannot both pass.
     *
     * @param proof the raw {@code DPoP} header value, already verified by {@link #verifyProof}
     */
    public boolean claimProof(String proof) {
        try {
            String jti = SignedJWT.parse(proof).getJWTClaimsSet().getJWTID();
            if (jti == null) {
                return false; // verifyProof already required one; a proof without it is not usable
            }
            return seenJti.asMap().putIfAbsent(jti, Boolean.TRUE) == null;
        } catch (Exception e) {
            log.debug("Could not read the jti of an already-verified DPoP proof: {}", e.toString());
            return false;
        }
    }

    private static String sha256Base64Url(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
            return Base64URL.encode(digest).toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
