package com.ebremer.lws.server.auth;

import java.util.Optional;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Validates an LWS did:key authentication credential, per
 * <a href="https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/">LWS Authentication:
 * Self-signed did:key</a>. The credential is a signed JWT whose {@code sub}, {@code iss} and
 * {@code client_id} are all the same {@code did:key:} URI; the verification key is extracted
 * directly from that identifier, so no network lookup is required.
 *
 * <p><b>Deprecated suite.</b> The did:key suite was discontinued on 18 September 2026: the
 * self-signed controlled identifier suite subsumes it, resolving a {@code did:key} subject to its DID
 * document and selecting the verification method the JWT's {@code kid} names. {@link SsiCidValidator}
 * now validates every did:key credential that carries a {@code kid}; this class is reached only for
 * one that does not, so credentials minted before the change keep working. It is no longer
 * advertised in the storage description.
 *
 * @author Erich Bremer
 */
public final class DidKeyValidator implements CredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(DidKeyValidator.class);

    private final AudiencePolicy audience;
    private final long maxLifetimeMs;

    /**
     * @param audience      audience policy; a did:key credential is self-minted, so without one a
     *                      token addressed to another storage would authenticate here
     * @param maxLifetimeMs maximum accepted token lifetime, or {@code <= 0} for unlimited
     */
    public DidKeyValidator(AudiencePolicy audience, long maxLifetimeMs) {
        this.audience = audience;
        this.maxLifetimeMs = maxLifetimeMs;
    }

    @Override
    public Optional<LwsPrincipal> validate(String credential) {
        try {
            SignedJWT jwt = SignedJWT.parse(credential);
            if (!JwsSupport.algNotNone(jwt)) {
                return Optional.empty();
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String sub = claims.getSubject();
            String iss = claims.getIssuer();
            String clientId = JwsSupport.clientId(claims);
            if (sub == null || !sub.startsWith(DidKey.PREFIX)) {
                return Optional.empty();
            }
            if (!sub.equals(iss) || !sub.equals(clientId)) {
                log.debug("did:key credential: sub/iss/client_id must be identical");
                return Optional.empty();
            }
            if (!audience.permits(claims)) {
                log.debug("did:key credential: aud does not name this storage");
                return Optional.empty();
            }
            JWK jwk = DidKey.toPublicJwk(sub);
            if (!JwsSupport.verify(jwt, jwk)) {
                log.debug("did:key credential: signature does not verify");
                return Optional.empty();
            }
            if (!JwsSupport.temporalClaimsValid(claims, maxLifetimeMs)) {
                log.debug("did:key credential: missing/expired exp, post-dated, or lifetime too long");
                return Optional.empty();
            }
            return Optional.of(new LwsPrincipal(sub, iss, clientId));
        } catch (Exception e) {
            log.debug("did:key validation failed: {}", e.toString());
            return Optional.empty();
        }
    }
}
