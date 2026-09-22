package com.ebremer.lws.server.auth;

import java.io.StringReader;
import java.net.URI;
import java.net.URL;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.core.JsonLimits;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Validates an OAuth 2.0 access token presented to this storage, per lws10-core, Token Validation
 * by a Storage Server — the baseline mechanism of the LWS authorization framework.
 *
 * <p>An access token is an RFC 9068 JWT ({@code typ: at+jwt}) issued by an authorization server
 * this storage trusts: the one embedded in it, and any listed in {@code lws.oauth.trusted-issuers}.
 * Each check lws10-core names is made, and the request is refused on any failure:
 *
 * <ul>
 *   <li><b>signature</b>, with the issuer's key — the embedded server's own, or one from the
 *       {@code jwks_uri} of an external server's metadata at
 *       {@code /.well-known/lws-configuration}. Keys are cached and re-fetched when a token names a
 *       {@code kid} the cache does not have, which is what key rotation needs;</li>
 *   <li><b>issuer</b>: {@code iss} is a trusted authorization server;</li>
 *   <li><b>audience</b>: {@code aud} holds exactly one value, and it identifies this storage;</li>
 *   <li><b>time</b>: before {@code exp}, not before {@code nbf}, {@code iat} not in the future —
 *       each with the usual clock-skew allowance.</li>
 * </ul>
 *
 * <p>The claims lws10-core requires of an access token — {@code sub}, {@code client_id} and
 * {@code jti} as well as the above — must be present. The principal is the subject, with the
 * authorization server as issuer and {@code client_id} as the client.
 *
 * @author Erich Bremer
 */
public final class AccessTokenValidator implements CredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(AccessTokenValidator.class);

    private static final long KEYS_TTL_MS = 60 * 60 * 1000L;
    private static final long KEYS_MISS_TTL_MS = 60 * 1000L;
    private static final int CONNECT_TIMEOUT_MS = 3_000;
    private static final int READ_TIMEOUT_MS = 5_000;
    private static final int MAX_JWKS_BYTES = 256 * 1024;

    private final Set<String> audiences;
    private final String localIssuer;
    private final JWKSource<SecurityContext> localKeys;
    private final Set<String> trustedIssuers;
    private final DocumentLoader loader;
    private final OutboundFetchPolicy fetchPolicy;

    private final Cache<String, JWKSource<SecurityContext>> remoteKeys = Caffeine.newBuilder()
            .expireAfterWrite(KEYS_TTL_MS, TimeUnit.MILLISECONDS).maximumSize(100).build();
    private final Cache<String, String> remoteFailures = Caffeine.newBuilder()
            .expireAfterWrite(KEYS_MISS_TTL_MS, TimeUnit.MILLISECONDS).maximumSize(100).build();

    /**
     * @param audiences      the values that identify this storage in {@code aud}: its URI, and the
     *                       same without the trailing slash
     * @param localIssuer    the embedded authorization server's issuer, or {@code null} if it is off
     * @param localKeys      its public signing keys, or {@code null} if it is off
     * @param trustedIssuers external authorization servers whose tokens are accepted
     * @param loader         the policy-checked loader for an external server's metadata
     * @param fetchPolicy    the outbound-fetch policy for its {@code jwks_uri}
     */
    public AccessTokenValidator(Set<String> audiences, String localIssuer, JWKSet localKeys,
            Set<String> trustedIssuers, DocumentLoader loader, OutboundFetchPolicy fetchPolicy) {
        this.audiences = Set.copyOf(audiences);
        this.localIssuer = localIssuer;
        this.localKeys = localKeys == null ? null : new ImmutableJWKSet<>(localKeys);
        this.trustedIssuers = Set.copyOf(trustedIssuers);
        this.loader = loader;
        this.fetchPolicy = fetchPolicy;
    }

    /** Whether tokens from {@code issuer} are accepted here. */
    public boolean trusts(String issuer) {
        return issuer != null && ((localIssuer != null && localIssuer.equals(issuer))
                || trustedIssuers.contains(issuer));
    }

    /** Whether a JWT declares itself an RFC 9068 access token ({@code typ} {@code at+jwt}). */
    public static boolean isAccessToken(SignedJWT jwt) {
        JOSEObjectType typ = jwt.getHeader().getType();
        if (typ == null) {
            return false;
        }
        String t = typ.getType().toLowerCase(Locale.ROOT);
        return t.equals("at+jwt") || t.equals("application/at+jwt");
    }

    @Override
    public Optional<LwsPrincipal> validate(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!isAccessToken(jwt)) {
                log.debug("access token: typ is not at+jwt (RFC 9068)");
                return Optional.empty();
            }
            JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
            if (!JwsSupport.algNotNone(jwt) || JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
                log.debug("access token: alg {} is not an asymmetric signature", alg);
                return Optional.empty();
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String iss = claims.getIssuer();
            if (!trusts(iss)) {
                log.debug("access token: issuer {} is not a trusted authorization server", iss);
                return Optional.empty();
            }
            if (!signatureVerifies(jwt, iss)) {
                log.debug("access token: signature does not verify with a key of {}", iss);
                return Optional.empty();
            }
            List<String> aud = claims.getAudience();
            if (aud == null || aud.size() != 1 || !audiences.contains(aud.get(0))) {
                log.debug("access token: aud {} is not exactly this storage", aud);
                return Optional.empty();
            }
            if (!timely(claims)) {
                log.debug("access token: expired, not yet valid, or issued in the future");
                return Optional.empty();
            }
            String sub = claims.getSubject();
            String clientId = claims.getStringClaim("client_id");
            if (sub == null || sub.isBlank() || clientId == null || clientId.isBlank()
                    || claims.getJWTID() == null) {
                log.debug("access token: sub, client_id and jti are required");
                return Optional.empty();
            }
            return Optional.of(new LwsPrincipal(sub, iss, clientId));
        } catch (Exception e) {
            log.debug("access token validation failed: {}", e.toString());
            return Optional.empty();
        }
    }

    private static boolean timely(JWTClaimsSet claims) {
        long now = System.currentTimeMillis();
        long skew = JwsSupport.CLOCK_SKEW_MS;
        Date exp = claims.getExpirationTime();
        Date nbf = claims.getNotBeforeTime();
        Date iat = claims.getIssueTime();
        return exp != null && exp.getTime() > now - skew
                && (nbf == null || nbf.getTime() <= now + skew)
                && iat != null && iat.getTime() <= now + skew;
    }

    /** Try the issuer's keys the token could have been signed with: by {@code kid} when it names one. */
    private boolean signatureVerifies(SignedJWT jwt, String iss) throws Exception {
        JWKSource<SecurityContext> source = localIssuer != null && localIssuer.equals(iss) ? localKeys : remoteKeys(iss);
        if (source == null) {
            return false;
        }
        String kid = jwt.getHeader().getKeyID();
        JWKMatcher.Builder matcher = new JWKMatcher.Builder();
        if (kid != null) {
            matcher.keyID(kid);
        }
        for (JWK jwk : source.get(new JWKSelector(matcher.build()), null)) {
            if (jwk.isPrivate()) {
                continue;
            }
            try {
                if (JwsSupport.verify(jwt, jwk)) {
                    return true;
                }
            } catch (Exception wrongKey) {
                // a key of another type or algorithm: try the next one
            }
        }
        return false;
    }

    /**
     * The key source for an external authorization server: its RFC 8414 metadata at
     * {@code /.well-known/lws-configuration} — inserted before any path component of the issuer —
     * whose {@code issuer} must be the configured one, and whose {@code jwks_uri} must pass the
     * outbound-fetch policy. Neither the metadata nor the key set follows a redirect.
     */
    private JWKSource<SecurityContext> remoteKeys(String iss) throws Exception {
        JWKSource<SecurityContext> cached = remoteKeys.getIfPresent(iss);
        if (cached != null) {
            return cached;
        }
        String failure = remoteFailures.getIfPresent(iss);
        if (failure != null) {
            throw new IllegalStateException("metadata for " + iss + " failed recently: " + failure);
        }
        try {
            String text = loader.load(metadataUrl(iss));
            if (text == null) {
                throw new IllegalStateException("no authorization server metadata at " + metadataUrl(iss));
            }
            JsonLimits.requireBoundedNesting(text, JsonLimits.MAX_NESTING_DEPTH);
            JsonObject metadata;
            try (JsonReader reader = Json.createReader(new StringReader(text))) {
                metadata = reader.readObject();
            }
            if (!iss.equals(metadata.getString("issuer", null))) {
                throw new IllegalStateException("metadata issuer does not match " + iss + " (RFC 8414 §3.3)");
            }
            String jwksUri = metadata.getString("jwks_uri", null);
            if (jwksUri == null || !fetchPolicy.permits(jwksUri)) {
                throw new IllegalStateException("jwks_uri " + jwksUri + " is missing or blocked by policy");
            }
            JWKSource<SecurityContext> source =
                    JWKSourceBuilder.<SecurityContext>create(URI.create(jwksUri).toURL(), RETRIEVER).build();
            remoteKeys.put(iss, source);
            return source;
        } catch (Exception e) {
            remoteFailures.put(iss, e.toString());
            throw e;
        }
    }

    /** RFC 8414 §3.1: the well-known suffix goes between the host and any path of the issuer. */
    static String metadataUrl(String issuer) {
        URI uri = URI.create(issuer);
        String path = uri.getRawPath() == null || uri.getRawPath().equals("/") ? "" : uri.getRawPath();
        String authority = uri.getRawAuthority();
        return uri.getScheme() + "://" + authority + "/.well-known/lws-configuration" + path;
    }

    /** Size- and time-bounded JWKS retrieval that does not follow redirects. */
    private static final com.nimbusds.jose.util.ResourceRetriever RETRIEVER =
            new com.nimbusds.jose.util.DefaultResourceRetriever(CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS, MAX_JWKS_BYTES) {
                @Override
                protected java.net.HttpURLConnection openConnection(URL url) throws java.io.IOException {
                    java.net.HttpURLConnection connection = super.openConnection(url);
                    connection.setInstanceFollowRedirects(false);
                    return connection;
                }
            };
}
