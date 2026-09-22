package com.ebremer.lws.server.auth;

import java.text.ParseException;
import java.util.Optional;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Entry point for LWS authentication at the storage: routes a presented credential to what can
 * validate it, by its shape, and returns the validated {@link LwsPrincipal}.
 *
 * <ul>
 *   <li>An <b>access token</b> — an RFC 9068 JWT ({@code typ: at+jwt}), or any JWT whose issuer is
 *       an authorization server this storage trusts — goes to the {@link AccessTokenValidator}.
 *       This is lws10-core's baseline: a client exchanges its authentication credential at an
 *       authorization server and presents the access token it gets. Such a token is never
 *       re-interpreted as an authentication credential if it fails.</li>
 * </ul>
 *
 * <p>Presenting an <b>authentication credential directly</b> is this server's behaviour from before
 * the baseline, kept as an additional mechanism (lws10-core: "A server MAY support additional
 * authorization mechanisms") unless {@code lws.oauth.accept-authentication-credentials} turns it off:
 *
 * <ul>
 *   <li>a self-issued JWT ({@code iss} equal to {@code sub}) &rarr; the self-signed controlled
 *       identifier suite, which covers HTTPS, {@code did:key} and {@code did:web} subjects;</li>
 *   <li>one whose subject is a {@code did:key} and that names no {@code kid} &rarr; the discontinued
 *       did:key suite, kept deprecated for credentials minted before the self-signed CID suite
 *       subsumed it (a CID credential must name the verification method it was signed with);</li>
 *   <li>any other JWT &rarr; the OpenID Connect suite;</li>
 *   <li>a non-JWT credential (a SAML assertion, possibly base64-encoded) &rarr; the SAML suite.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class LwsCredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(LwsCredentialValidator.class);

    private final LwsOpenIdValidator openId;
    private final SsiCidValidator ssiCid;
    private final DidKeyValidator didKey;
    private final SamlValidator saml; // nullable: only when SAML trust is configured
    private final AccessTokenValidator accessTokens; // nullable: no authorization server is trusted
    private final boolean acceptCredentials;

    /** Direct credentials only, and no access tokens: the pre-baseline behaviour, for tests and tools. */
    public LwsCredentialValidator(LwsOpenIdValidator openId, SsiCidValidator ssiCid,
            DidKeyValidator didKey, SamlValidator saml) {
        this(openId, ssiCid, didKey, saml, null, true);
    }

    public LwsCredentialValidator(LwsOpenIdValidator openId, SsiCidValidator ssiCid,
            DidKeyValidator didKey, SamlValidator saml, AccessTokenValidator accessTokens,
            boolean acceptCredentials) {
        this.openId = openId;
        this.ssiCid = ssiCid;
        this.didKey = didKey;
        this.saml = saml;
        this.accessTokens = accessTokens;
        this.acceptCredentials = acceptCredentials;
    }

    /**
     * Whether {@code subject}'s own controlled-identifier document names {@code issuer} as its
     * OpenID provider — the subject-trusts-issuer half of the OpenID suite, on its own.
     *
     * <p>For a caller that has already had the ID token validated for it by an OpenID client, and
     * so needs the trust step but not the signature step. The interactive browser login is the one
     * such caller: pac4j verifies the token's signature, issuer, expiry, nonce and audience during
     * the callback, but nothing there asks whether the subject actually claims that issuer.
     * {@code subject} must come from an already-authenticated token, because resolving it
     * dereferences a URL the token supplied.
     */
    public boolean openIdSubjectTrustsIssuer(String subject, String issuer) {
        return subject != null && issuer != null && openId.trusts(subject, issuer);
    }

    public Optional<LwsPrincipal> validate(String credential) {
        if (credential == null || credential.isBlank()) {
            return Optional.empty();
        }
        String c = credential.trim();
        try {
            SignedJWT jwt = SignedJWT.parse(c);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String sub = claims.getSubject();
            String iss = claims.getIssuer();
            if (AccessTokenValidator.isAccessToken(jwt) || (accessTokens != null && accessTokens.trusts(iss))) {
                return accessTokens == null ? Optional.empty() : accessTokens.validate(c);
            }
            if (!acceptCredentials) {
                log.debug("an authentication credential was presented directly, which this storage does not accept");
                return Optional.empty();
            }
            if (sub != null && sub.startsWith(DidKey.PREFIX) && jwt.getHeader().getKeyID() == null) {
                log.debug("did:key credential without a kid: validated by the discontinued did:key suite");
                return didKey.validate(c);
            }
            if (sub != null && sub.equals(iss)) {
                return ssiCid.validate(c);
            }
            return openId.validate(c);
        } catch (ParseException notAJwt) {
            return saml == null || !acceptCredentials ? Optional.empty() : saml.validate(c);
        }
    }
}
