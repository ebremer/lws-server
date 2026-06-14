package com.ebremer.lws.server.auth;

import java.net.URI;
import java.net.URL;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.riot.RDFDataMgr;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Validates an LWS OpenID Connect authentication credential, per
 * <a href="https://w3c.github.io/lws-protocol/lws10-authn-openid/">LWS Authentication: OpenID
 * Connect</a>.
 *
 * <p>The credential is an OIDC ID Token (a signed JWT). Validation:
 * <ol>
 *   <li>parse the JWT and read {@code sub} (subject), {@code iss} (issuer), {@code azp} (client);</li>
 *   <li>reject any token whose signing algorithm is {@code none};</li>
 *   <li>establish trust between subject and issuer: dereference {@code sub} to a controlled
 *       identifier document and confirm it advertises a service of type
 *       {@code lws:OpenIdProvider} whose {@code serviceEndpoint} equals {@code iss};</li>
 *   <li>perform OIDC discovery on {@code iss}, fetch its JWKS and verify the JWT signature,
 *       expiry and issuer per OpenID Connect Core.</li>
 * </ol>
 *
 * Discovery/JWKS results and subject→issuer trust are cached with short TTLs.
 *
 * @author Erich Bremer
 */
public final class LwsOpenIdValidator {

    private static final Logger log = LoggerFactory.getLogger(LwsOpenIdValidator.class);

    private static final long JWKS_TTL_MS = 60 * 60 * 1000L;   // 1 hour
    private static final long TRUST_TTL_MS = 10 * 60 * 1000L;  // 10 minutes

    /** The CID v1 context maps {@code service}/{@code serviceEndpoint} into the DID namespace. */
    private static final String DID_SERVICE_ENDPOINT = "https://www.w3.org/ns/did#serviceEndpoint";

    // Bounded, TTL-evicting caches: a per-issuer JWKS source, and per-(subject,issuer) trust. Caffeine
    // handles expiry and size eviction, so no manual TTL checks or cleanup are needed.
    private final Cache<String, JWKSource<SecurityContext>> jwksByIssuer = Caffeine.newBuilder()
            .expireAfterWrite(JWKS_TTL_MS, TimeUnit.MILLISECONDS).maximumSize(1_000).build();
    private final Cache<String, Boolean> trustCache = Caffeine.newBuilder()
            .expireAfterWrite(TRUST_TTL_MS, TimeUnit.MILLISECONDS).maximumSize(10_000).build();

    private final OutboundFetchPolicy fetchPolicy;

    public LwsOpenIdValidator(OutboundFetchPolicy fetchPolicy) {
        this.fetchPolicy = fetchPolicy;
    }

    /** Validate a raw bearer/DPoP token value (the JWT itself, scheme already stripped). */
    public Optional<LwsPrincipal> validate(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
            if (alg == null || "none".equalsIgnoreCase(alg.getName())) {
                log.debug("Rejecting token with no/invalid signing algorithm");
                return Optional.empty();
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String iss = claims.getIssuer();
            String sub = claims.getSubject();
            if (iss == null || sub == null) {
                log.debug("Token missing iss/sub");
                return Optional.empty();
            }
            String azp = claims.getStringClaim("azp");

            if (!isTrusted(sub, iss)) {
                log.debug("Subject {} does not trust issuer {}", sub, iss);
                return Optional.empty();
            }

            JWKSource<SecurityContext> jwks = jwksFor(iss);
            ConfigurableJWTProcessor<SecurityContext> proc = new DefaultJWTProcessor<>();
            proc.setJWSKeySelector(new JWSVerificationKeySelector<>(alg, jwks));
            proc.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                    new JWTClaimsSet.Builder().issuer(iss).build(),
                    Set.of("sub", "exp")));
            proc.process(jwt, null); // throws on bad signature / expiry / issuer

            return Optional.of(new LwsPrincipal(sub, iss, azp));
        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.toString());
            return Optional.empty();
        }
    }

    /**
     * Confirm the subject's controlled-identifier document trusts the issuer as an OpenID
     * provider. Cached per (subject, issuer).
     */
    private boolean isTrusted(String sub, String iss) {
        String key = sub + '|' + iss;
        if (trustCache.getIfPresent(key) != null) {
            return true;
        }
        if (!fetchPolicy.permits(sub)) {
            log.debug("Refusing to dereference subject document {} (blocked by outbound-fetch policy)", sub);
            return false;
        }
        Model cid;
        try {
            cid = RDFDataMgr.loadModel(sub);
        } catch (RuntimeException e) {
            log.debug("Could not dereference subject document {}: {}", sub, e.toString());
            return false;
        }
        // A spec-shaped controlled identifier document (CID v1 context) expresses the endpoint as
        // did:serviceEndpoint; documents written directly in the LWS vocabulary are accepted too.
        ParameterizedSparqlString ask = new ParameterizedSparqlString();
        ask.setCommandText("""
                ASK {
                  ?svc a <%s> ; (<%s>|<%s>) ?iss .
                  FILTER( str(?iss) = str(?issuer) )
                }""".formatted(LWS.OpenIdProvider.getURI(), DID_SERVICE_ENDPOINT, LWS.serviceEndpoint.getURI()));
        ask.setIri("issuer", iss);
        boolean trusted;
        try (org.apache.jena.query.QueryExecution qe =
                org.apache.jena.query.QueryExecutionFactory.create(ask.asQuery(), cid)) {
            trusted = qe.execAsk();
        } catch (RuntimeException e) {
            log.debug("Trust query failed for {}: {}", sub, e.toString());
            return false;
        }
        if (trusted) {
            trustCache.put(key, Boolean.TRUE);
        }
        return trusted;
    }

    private JWKSource<SecurityContext> jwksFor(String iss) throws Exception {
        JWKSource<SecurityContext> cached = jwksByIssuer.getIfPresent(iss);
        if (cached != null) {
            return cached;
        }
        if (!fetchPolicy.permits(iss)) {
            throw new IllegalStateException("Issuer " + iss + " blocked by outbound-fetch policy");
        }
        OIDCProviderMetadata metadata = OIDCProviderMetadata.resolve(new Issuer(iss));
        URI jwksUri = metadata.getJWKSetURI();
        if (jwksUri == null) {
            throw new IllegalStateException("Issuer " + iss + " has no jwks_uri");
        }
        if (!fetchPolicy.permits(jwksUri.toString())) {
            throw new IllegalStateException("jwks_uri " + jwksUri + " blocked by outbound-fetch policy");
        }
        URL jwksUrl = jwksUri.toURL();
        JWKSource<SecurityContext> source = JWKSourceBuilder.create(jwksUrl).build();
        jwksByIssuer.put(iss, source);
        return source;
    }
}
