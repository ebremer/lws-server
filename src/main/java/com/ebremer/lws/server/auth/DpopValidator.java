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

    /** Upper bound on retained {@code jti} entries; bounds memory under high request volume. */
    private static final long MAX_JTI = 100_000L;

    private final long maxAgeMs;
    private final long skewMs;
    private final DpopNonceService nonceService; // null => nonces not required
    // Replay guard: a bounded, TTL-evicting cache of seen jti (entries expire after the acceptance window).
    private final Cache<String, Boolean> seenJti;

    public DpopValidator() {
        this(300_000L, 60_000L, null);
    }

    public DpopValidator(DpopNonceService nonceService) {
        this(300_000L, 60_000L, nonceService);
    }

    public DpopValidator(long maxAgeMs, long skewMs, DpopNonceService nonceService) {
        this.maxAgeMs = maxAgeMs;
        this.skewMs = skewMs;
        this.nonceService = nonceService;
        this.seenJti = Caffeine.newBuilder()
                .expireAfterWrite(maxAgeMs, TimeUnit.MILLISECONDS)
                .maximumSize(MAX_JTI)
                .build();
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
            String jti = claims.getJWTID();
            if (jti == null || !recordJti(jti)) {
                return Optional.empty(); // missing jti or replay
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
     * Record a {@code jti}, returning {@code false} if it was already seen within the acceptance
     * window (a replay). Caffeine evicts entries after the window ({@code maxAgeMs}, via
     * {@code expireAfterWrite}) so an expired {@code jti} is absent and treated as fresh, and bounds
     * the map at {@link #MAX_JTI}; a still-unexpired entry could be evicted only under sustained,
     * abnormal request volume.
     */
    private boolean recordJti(String jti) {
        return seenJti.asMap().putIfAbsent(jti, Boolean.TRUE) == null;
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
