package com.ebremer.lws.server.auth;

import java.text.ParseException;
import java.util.Optional;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Entry point for LWS authentication: routes a presented credential to the right authentication
 * suite by inspecting its shape, then returns the validated {@link LwsPrincipal}.
 *
 * <ul>
 *   <li>A signed JWT whose {@code sub} is a {@code did:key:} URI &rarr; did:key suite.</li>
 *   <li>A signed JWT whose {@code iss} equals its {@code sub} (self-issued) &rarr; SSI-CID suite.</li>
 *   <li>Any other signed JWT &rarr; OpenID Connect suite (external provider).</li>
 *   <li>A non-JWT credential (a SAML assertion, possibly base64-encoded) &rarr; SAML suite.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class LwsCredentialValidator {

    private final LwsOpenIdValidator openId;
    private final SsiCidValidator ssiCid;
    private final DidKeyValidator didKey;
    private final SamlValidator saml; // nullable: only when SAML trust is configured

    public LwsCredentialValidator(LwsOpenIdValidator openId, SsiCidValidator ssiCid,
            DidKeyValidator didKey, SamlValidator saml) {
        this.openId = openId;
        this.ssiCid = ssiCid;
        this.didKey = didKey;
        this.saml = saml;
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
            if (sub != null && sub.startsWith(DidKey.PREFIX)) {
                return didKey.validate(c);
            }
            if (sub != null && sub.equals(iss)) {
                return ssiCid.validate(c);
            }
            return openId.validate(c);
        } catch (ParseException notAJwt) {
            return saml == null ? Optional.empty() : saml.validate(c);
        }
    }
}
