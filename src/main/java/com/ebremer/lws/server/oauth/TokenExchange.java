package com.ebremer.lws.server.oauth;

import java.net.URI;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.CredentialValidator;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * The embedded authorization server's OAuth 2.0 Token Exchange (RFC 8693), as lws10-core,
 * Authorization, specifies it: a client presents an authentication credential as the
 * {@code subject_token} and this storage as the {@code resource}, and receives an RFC 9068 access
 * token for this storage.
 *
 * <p>The credential is validated by the authentication suite its {@code subject_token_type} names —
 * {@code …:id_token} for OpenID Connect, {@code …:jwt} for a self-signed controlled identifier
 * credential, {@code …:saml2} for SAML when an IdP is trusted — with the credential's audience
 * required to name this authorization server. The access token then carries:
 *
 * <ul>
 *   <li>{@code iss} — this authorization server, which is this storage's base URI;</li>
 *   <li>{@code sub} and {@code client_id} — the credential's subject and client, both URIs;</li>
 *   <li>{@code aud} — exactly the storage URI, which is the only {@code resource} accepted: this
 *       authorization server issues tokens for this storage and refuses every other one, as
 *       lws10-core requires of an unknown or untrusted storage;</li>
 *   <li>{@code exp}, {@code iat}, {@code jti} — a lifetime of
 *       {@code lws.oauth.access-token-lifetime-seconds} (300 by default, as lws10-core recommends),
 *       never outliving the credential it was exchanged for;</li>
 *   <li>{@code cnf.jkt} when the request carried a DPoP proof (RFC 9449 §5), in which case the token
 *       type is {@code DPoP} and the storage will accept it only with a proof by the same key.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class TokenExchange {

    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
    public static final String TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";
    public static final String TYPE_SAML2 = "urn:ietf:params:oauth:token-type:saml2";
    public static final String TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    /** The spelling lws10-core's own metadata example uses; accepted as {@link #TYPE_ID_TOKEN}. */
    private static final String TYPE_ID_TOKEN_HYPHENATED = "urn:ietf:params:oauth:token-type:id-token";

    /** An OAuth 2.0 error response (RFC 6749 §5.2). */
    public static final class OAuthError extends RuntimeException {
        private final int status;
        private final String error;

        public OAuthError(int status, String error, String description) {
            super(description);
            this.status = status;
            this.error = error;
        }

        public int status() {
            return status;
        }

        public String error() {
            return error;
        }
    }

    /** An issued access token, as the token response reports it (RFC 6749 §5.1, RFC 8693 §2.2.1). */
    public record Issued(String accessToken, String tokenType, long expiresIn) {
    }

    private final LwsConfiguration config;
    private final AccessTokenKeys keys;
    private final CredentialValidator openId;
    private final CredentialValidator selfSigned;
    private final CredentialValidator saml; // nullable: SAML is not configured
    private final Clock clock;

    /**
     * @param openId     the OpenID Connect suite, audience-bound to this authorization server
     * @param selfSigned the self-signed controlled identifier suite (with the deprecated did:key
     *                   fallback), audience-bound to this authorization server
     * @param saml       the SAML suite, or {@code null} when no IdP is trusted
     */
    public TokenExchange(LwsConfiguration config, AccessTokenKeys keys, CredentialValidator openId,
            CredentialValidator selfSigned, CredentialValidator saml, Clock clock) {
        this.config = config;
        this.keys = keys;
        this.openId = openId;
        this.selfSigned = selfSigned;
        this.saml = saml;
        this.clock = clock;
    }

    /** The subject token types this authorization server accepts, for its metadata. */
    public List<String> subjectTokenTypes() {
        return saml == null ? List.of(TYPE_ID_TOKEN, TYPE_JWT) : List.of(TYPE_ID_TOKEN, TYPE_JWT, TYPE_SAML2);
    }

    /**
     * Exchange a credential for an access token.
     *
     * @param params the token request's parameters, each present at most once
     * @param dpopJkt the thumbprint of a verified DPoP proof key, or {@code null}
     * @throws OAuthError for a request that cannot be honoured
     */
    public Issued exchange(Map<String, String> params, String dpopJkt) {
        String grantType = params.get("grant_type");
        if (grantType == null) {
            throw new OAuthError(400, "invalid_request", "grant_type is required");
        }
        if (!GRANT_TYPE.equals(grantType)) {
            throw new OAuthError(400, "unsupported_grant_type",
                    "this authorization server supports only " + GRANT_TYPE);
        }
        String resource = params.get("resource");
        if (resource == null || resource.isBlank()) {
            throw new OAuthError(400, "invalid_request", "resource is required: the URI of the storage");
        }
        if (!identifiesThisStorage(resource)) {
            throw new OAuthError(400, "invalid_target", "this authorization server issues tokens only for "
                    + config.storageIri());
        }
        String audience = params.get("audience");
        if (audience != null && !identifiesThisStorage(audience)) {
            throw new OAuthError(400, "invalid_target", "audience must identify " + config.storageIri());
        }
        String requested = params.get("requested_token_type");
        if (requested != null && !requested.equals(TYPE_ACCESS_TOKEN)) {
            throw new OAuthError(400, "invalid_request", "only " + TYPE_ACCESS_TOKEN + " can be issued");
        }
        if (params.containsKey("actor_token")) {
            throw new OAuthError(400, "invalid_request", "delegation (actor_token) is not supported");
        }
        String subjectToken = params.get("subject_token");
        String subjectTokenType = params.get("subject_token_type");
        if (subjectToken == null || subjectToken.isBlank() || subjectTokenType == null) {
            throw new OAuthError(400, "invalid_request", "subject_token and subject_token_type are required");
        }

        CredentialValidator suite = switch (subjectTokenType) {
            case TYPE_ID_TOKEN, TYPE_ID_TOKEN_HYPHENATED -> openId;
            case TYPE_JWT -> selfSigned;
            case TYPE_SAML2 -> saml;
            default -> null;
        };
        if (suite == null) {
            throw new OAuthError(400, "invalid_request", "unsupported subject_token_type " + subjectTokenType);
        }
        Optional<LwsPrincipal> validated = suite.validate(subjectToken);
        if (validated.isEmpty()) {
            throw new OAuthError(400, "invalid_request",
                    "the subject_token is not a valid authentication credential for this authorization server");
        }
        LwsPrincipal principal = validated.get();
        if (!isUri(principal.webId())) {
            throw new OAuthError(400, "invalid_request", "the credential's subject is not a URI");
        }
        if (!isUri(principal.clientId())) {
            throw new OAuthError(400, "invalid_request",
                    "the credential names no client, or its client is not a URI (an ID token needs azp)");
        }

        Instant now = clock.instant();
        Instant exp = now.plusSeconds(config.oauthAccessTokenLifetimeSeconds());
        Instant credentialExp = jwtExpiry(subjectToken);
        if (credentialExp != null && credentialExp.isBefore(exp)) {
            exp = credentialExp; // an access token never outlives what it was exchanged for
        }
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(config.oauthIssuer())
                .subject(principal.webId())
                .claim("client_id", principal.clientId())
                .audience(config.storageIri())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(exp))
                .jwtID(UUID.randomUUID().toString());
        if (dpopJkt != null) {
            claims.claim("cnf", Map.of("jkt", dpopJkt));
        }
        long expiresIn = Math.max(0, exp.getEpochSecond() - now.getEpochSecond());
        return new Issued(keys.sign(claims.build()), dpopJkt != null ? "DPoP" : "Bearer", expiresIn);
    }

    /** The storage URI, or the base URI it is — with or without the trailing slash. */
    private boolean identifiesThisStorage(String uri) {
        return uri.equals(config.storageIri()) || uri.equals(config.baseUri());
    }

    private static boolean isUri(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        try {
            return new URI(value).getScheme() != null;
        } catch (Exception e) {
            return false;
        }
    }

    private static Instant jwtExpiry(String token) {
        try {
            Date exp = SignedJWT.parse(token).getJWTClaimsSet().getExpirationTime();
            return exp == null ? null : exp.toInstant();
        } catch (ParseException notAJwt) {
            return null;
        }
    }
}
