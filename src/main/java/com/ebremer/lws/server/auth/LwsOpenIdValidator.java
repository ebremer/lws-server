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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Validates an LWS OpenID Connect authentication credential, per
 * <a href="https://w3c.github.io/lws-protocol/lws10-authn-openid/">LWS Authentication: OpenID
 * Connect</a>.
 *
 * <p>The credential is an OIDC ID Token (a signed JWT). Validation, in this order:
 * <ol>
 *   <li>parse the JWT and read {@code sub} (subject), {@code iss} (issuer), {@code azp} (client);</li>
 *   <li>reject any token whose signing algorithm is {@code none};</li>
 *   <li>check {@code aud} against this storage's accepted audiences, so a token minted for a
 *       different relying party of the same provider cannot be replayed here;</li>
 *   <li>perform OIDC discovery on {@code iss}, fetch its JWKS and verify the JWT signature,
 *       expiry and issuer per OpenID Connect Core;</li>
 *   <li><em>only then</em> establish trust between subject and issuer: dereference {@code sub} to a
 *       controlled identifier document and confirm that <em>the subject itself</em> links to a
 *       service of type {@code lws:OpenIdProvider} whose {@code serviceEndpoint} equals
 *       {@code iss}. The link must start at the subject — a provider named anywhere else in the
 *       document, by a neighbour the profile happens to describe, is not the subject's claim.</li>
 * </ol>
 *
 * <p>The ordering of (3)–(5) is deliberate. The subject document is fetched from a URL the token
 * supplies, so doing it before the signature is verified lets an unauthenticated caller drive an
 * outbound request per attempt. Verifying the signature first means an attacker must already hold a
 * token the issuer really signed. The fetch itself goes through a {@link DocumentLoader}, which
 * bounds size and time and re-applies the {@link OutboundFetchPolicy} to every redirect hop.
 *
 * <p>Discovery/JWKS results and subject&rarr;issuer trust are cached with short TTLs; failed trust
 * lookups are negatively cached briefly so a hostile subject cannot force a fetch per request.
 *
 * @author Erich Bremer
 */
public final class LwsOpenIdValidator {

    private static final Logger log = LoggerFactory.getLogger(LwsOpenIdValidator.class);

    private static final long JWKS_TTL_MS = 60 * 60 * 1000L;        // 1 hour
    private static final long JWKS_MISS_TTL_MS = 60 * 1000L;        // 1 minute (negative)
    private static final long TRUST_TTL_MS = 10 * 60 * 1000L;       // 10 minutes
    private static final long TRUST_MISS_TTL_MS = 60 * 1000L;       // 1 minute (negative)

    /** Bounds on OIDC discovery, which runs on the request thread against an untrusted issuer. */
    private static final int DISCOVERY_CONNECT_TIMEOUT_MS = 3_000;
    private static final int DISCOVERY_READ_TIMEOUT_MS = 5_000;
    /** Bound on a fetched JWK set; a key set is a few kilobytes and the source is untrusted. */
    private static final int MAX_JWKS_BYTES = 256 * 1024;

    /** The CID v1 context maps {@code service}/{@code serviceEndpoint} into the DID namespace. */
    private static final String DID_SERVICE = "https://www.w3.org/ns/did#service";
    private static final String DID_SERVICE_ENDPOINT = "https://www.w3.org/ns/did#serviceEndpoint";

    // Bounded, TTL-evicting caches: a per-issuer JWKS source, and per-(subject,issuer) trust. Caffeine
    // handles expiry and size eviction, so no manual TTL checks or cleanup are needed.
    private final Cache<String, JWKSource<SecurityContext>> jwksByIssuer = Caffeine.newBuilder()
            .expireAfterWrite(JWKS_TTL_MS, TimeUnit.MILLISECONDS).maximumSize(1_000).build();
    // Issuers whose discovery failed, held briefly. Discovery is reached with an issuer the token
    // chose, so without this a hostile `iss` costs one outbound request per presentation even after
    // the first has already failed (finding M4). Only genuine failures land here, so a healthy
    // issuer can never be poisoned into it: its discovery succeeds and is cached positively instead.
    private final Cache<String, String> jwksFailures = Caffeine.newBuilder()
            .expireAfterWrite(JWKS_MISS_TTL_MS, TimeUnit.MILLISECONDS).maximumSize(10_000).build();
    private final Cache<String, Boolean> trustCache = Caffeine.newBuilder()
            .expireAfterWrite(TRUST_TTL_MS, TimeUnit.MILLISECONDS).maximumSize(10_000).build();
    private final Cache<String, Boolean> trustMissCache = Caffeine.newBuilder()
            .expireAfterWrite(TRUST_MISS_TTL_MS, TimeUnit.MILLISECONDS).maximumSize(10_000).build();

    private final OutboundFetchPolicy fetchPolicy;
    private final DocumentLoader loader;
    private final AudiencePolicy audience;

    public LwsOpenIdValidator(OutboundFetchPolicy fetchPolicy, DocumentLoader loader, AudiencePolicy audience) {
        this.fetchPolicy = fetchPolicy;
        this.loader = loader;
        this.audience = audience;
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
            if (!audience.permits(claims)) {
                log.debug("Token audience {} does not name this storage", claims.getAudience());
                return Optional.empty();
            }
            String azp = claims.getStringClaim("azp");

            JWKSource<SecurityContext> jwks = jwksFor(iss);
            ConfigurableJWTProcessor<SecurityContext> proc = new DefaultJWTProcessor<>();
            proc.setJWSKeySelector(new JWSVerificationKeySelector<>(alg, jwks));
            proc.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                    new JWTClaimsSet.Builder().issuer(iss).build(),
                    Set.of("sub", "exp")));
            proc.process(jwt, null); // throws on bad signature / expiry / issuer

            // Only a token this issuer really signed gets to drive a subject-document fetch.
            if (!trusts(sub, iss)) {
                log.debug("Subject {} does not trust issuer {}", sub, iss);
                return Optional.empty();
            }

            return Optional.of(new LwsPrincipal(sub, iss, azp));
        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.toString());
            return Optional.empty();
        }
    }

    /**
     * Confirm that <em>the subject</em> names this issuer as its OpenID provider, in the subject's
     * own controlled-identifier document. Cached per (subject, issuer), positively and negatively.
     *
     * <p><b>Callers must already have established that the token was genuinely issued.</b> This
     * dereferences a URL the token supplies, so calling it on an unverified subject hands an
     * unauthenticated caller an outbound request per attempt. {@link #validate} calls it only after
     * the signature checks out; the interactive login path calls it only on a profile pac4j has
     * already authenticated.
     */
    public boolean trusts(String sub, String iss) {
        String key = sub + '|' + iss;
        if (trustCache.getIfPresent(key) != null) {
            return true;
        }
        if (trustMissCache.getIfPresent(key) != null) {
            return false;
        }
        // A controlled identifier document is JSON first (CID 1.0), and is usually served as such —
        // application/json, application/cid — where the RDF path below cannot even parse it. Read
        // it as JSON when it is JSON; fall back to RDF for a document written in Turtle or another
        // RDF syntax.
        Boolean json = trustsAsJson(sub, iss);
        if (json != null) {
            (json ? trustCache : trustMissCache).put(key, Boolean.TRUE);
            return json;
        }
        Model cid = loader.loadRdf(sub);
        if (cid == null) {
            log.debug("Could not dereference subject document {}", sub);
            trustMissCache.put(key, Boolean.TRUE);
            return false;
        }
        // Anchored to the subject, and that anchoring is the whole point: without the
        // ?subject service ?svc hop this asks only "does this document mention, anywhere, some
        // service of type lws:OpenIdProvider pointing at this issuer?" — which any node in the
        // graph can satisfy. Profile documents routinely describe other people (foaf:knows, an
        // aggregator, a shared document), so a subject that names no provider at all would inherit
        // trust from a neighbour that does.
        //
        // A spec-shaped controlled identifier document (CID v1 context) expresses the link as
        // did:service/did:serviceEndpoint; documents written directly in the LWS vocabulary are
        // accepted too, and the two may be mixed.
        ParameterizedSparqlString ask = new ParameterizedSparqlString();
        ask.setCommandText("""
                ASK {
                  ?subject (<%s>|<%s>) ?svc .
                  ?svc a <%s> ; (<%s>|<%s>) ?iss .
                  FILTER( str(?iss) = str(?issuer) )
                }""".formatted(DID_SERVICE, LWS.service.getURI(),
                LWS.OpenIdProvider.getURI(), DID_SERVICE_ENDPOINT, LWS.serviceEndpoint.getURI()));
        ask.setIri("subject", sub);
        ask.setIri("issuer", iss);
        boolean trusted;
        try (org.apache.jena.query.QueryExecution qe =
                org.apache.jena.query.QueryExecutionFactory.create(ask.asQuery(), cid)) {
            trusted = qe.execAsk();
        } catch (RuntimeException e) {
            log.debug("Trust query failed for {}: {}", sub, e.toString());
            trustMissCache.put(key, Boolean.TRUE);
            return false;
        }
        if (trusted) {
            trustCache.put(key, Boolean.TRUE);
        } else {
            trustMissCache.put(key, Boolean.TRUE);
        }
        return trusted;
    }

    /**
     * The subject-trusts-issuer check over the document read as JSON: the topmost map's {@code id}
     * must be the subject, and one of <em>its</em> {@code service} entries must have type
     * {@code https://www.w3.org/ns/lws#OpenIdProvider} and {@code serviceEndpoint} equal to the
     * issuer — the lws10-authn-openid rule, on the document shape the suite's own example uses.
     *
     * @return the answer, or {@code null} when the document is not JSON (so the RDF check decides)
     */
    private Boolean trustsAsJson(String sub, String iss) {
        String text = loader.load(sub);
        if (text == null) {
            return null;
        }
        jakarta.json.JsonObject doc;
        try {
            com.ebremer.lws.server.core.JsonLimits.requireBoundedNesting(text,
                    com.ebremer.lws.server.core.JsonLimits.MAX_NESTING_DEPTH);
            try (jakarta.json.JsonReader reader = jakarta.json.Json.createReader(new java.io.StringReader(text))) {
                doc = reader.readObject();
            }
        } catch (RuntimeException | StackOverflowError notJson) {
            return null;
        }
        if (!sub.equals(doc.getString("id", null))) {
            log.debug("Subject document id does not equal the subject {}", sub);
            return false;
        }
        boolean lwsContext = doc.containsKey("@context") && doc.get("@context").toString()
                .contains(com.ebremer.lws.server.vocab.LWS.JSON_CONTEXT);
        jakarta.json.JsonValue services = doc.get("service");
        if (services == null) {
            return false;
        }
        java.util.List<jakarta.json.JsonValue> entries = services.getValueType() == jakarta.json.JsonValue.ValueType.ARRAY
                ? services.asJsonArray() : java.util.List.of(services);
        for (jakarta.json.JsonValue entry : entries) {
            if (entry.getValueType() != jakarta.json.JsonValue.ValueType.OBJECT) {
                continue;
            }
            jakarta.json.JsonObject service = entry.asJsonObject();
            if (isOpenIdProvider(service.get("type"), lwsContext) && endpointIs(service.get("serviceEndpoint"), iss)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isOpenIdProvider(jakarta.json.JsonValue type, boolean lwsContext) {
        if (type == null) {
            return false;
        }
        java.util.List<jakarta.json.JsonValue> values = type.getValueType() == jakarta.json.JsonValue.ValueType.ARRAY
                ? type.asJsonArray() : java.util.List.of(type);
        for (jakarta.json.JsonValue v : values) {
            if (v.getValueType() != jakarta.json.JsonValue.ValueType.STRING) {
                continue;
            }
            String t = ((jakarta.json.JsonString) v).getString();
            if (t.equals(LWS.OpenIdProvider.getURI()) || (lwsContext && t.equals("OpenIdProvider"))) {
                return true;
            }
        }
        return false;
    }

    private static boolean endpointIs(jakarta.json.JsonValue endpoint, String iss) {
        if (endpoint == null) {
            return false;
        }
        if (endpoint.getValueType() == jakarta.json.JsonValue.ValueType.STRING) {
            return iss.equals(((jakarta.json.JsonString) endpoint).getString());
        }
        if (endpoint.getValueType() == jakarta.json.JsonValue.ValueType.ARRAY) {
            for (jakarta.json.JsonValue v : endpoint.asJsonArray()) {
                if (v.getValueType() == jakarta.json.JsonValue.ValueType.STRING
                        && iss.equals(((jakarta.json.JsonString) v).getString())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * The JWKS source for an issuer, discovered once per {@link #JWKS_TTL_MS} and — when discovery
     * fails — <em>not</em> retried for {@link #JWKS_MISS_TTL_MS} (finding M4).
     *
     * <p>Both bounds exist for the same reason: this runs on the request thread with an issuer the
     * presented token named, before anything about that token has been trusted. The timeouts stop a
     * hanging issuer pinning a worker (the no-argument {@code resolve()} overload compiles to
     * {@code resolve(issuer, null, 0, 0)} — no connect timeout and no read timeout at all); the
     * negative cache stops a repeatedly-failing one costing an outbound request per presentation.
     * The negative TTL is kept short so a real issuer's transient outage clears in a minute.
     */
    private JWKSource<SecurityContext> jwksFor(String iss) throws Exception {
        JWKSource<SecurityContext> cached = jwksByIssuer.getIfPresent(iss);
        if (cached != null) {
            return cached;
        }
        String recentFailure = jwksFailures.getIfPresent(iss);
        if (recentFailure != null) {
            throw new IllegalStateException(
                    "Discovery for issuer " + iss + " failed recently and is not being retried yet: "
                            + recentFailure);
        }
        try {
            if (!fetchPolicy.permits(iss)) {
                throw new IllegalStateException("Issuer " + iss + " blocked by outbound-fetch policy");
            }
            OIDCProviderMetadata metadata = OIDCProviderMetadata.resolve(new Issuer(iss), DISCOVERY_REQUEST);
            URI jwksUri = metadata.getJWKSetURI();
            if (jwksUri == null) {
                throw new IllegalStateException("Issuer " + iss + " has no jwks_uri");
            }
            if (!fetchPolicy.permits(jwksUri.toString())) {
                throw new IllegalStateException("jwks_uri " + jwksUri + " blocked by outbound-fetch policy");
            }
            URL jwksUrl = jwksUri.toURL();
            JWKSource<SecurityContext> source =
                    JWKSourceBuilder.<SecurityContext>create(jwksUrl, JWKS_RETRIEVER).build();
            jwksByIssuer.put(iss, source);
            return source;
        } catch (Exception e) {
            jwksFailures.put(iss, e.toString());
            throw e;
        }
    }

    /**
     * Both outbound legs of OIDC validation refuse to follow redirects.
     *
     * <p>The outbound-fetch policy is applied to the issuer and again to the {@code jwks_uri} it
     * advertises, but a policy check only covers the address it was given. Both libraries followed
     * {@code 3xx} on their own: {@code OIDCProviderMetadata.resolve} through the SDK's default
     * {@code HTTPRequest}, and the JWKS fetch through {@code DefaultResourceRetriever}, whose
     * {@code openHTTPConnection} is a bare {@code URL.openConnection()} — and {@code HttpURLConnection}
     * follows redirects by default. A public, policy-approved {@code jwks_uri} could therefore
     * {@code 302} the server to {@code 169.254.169.254} and the response would be read unchecked,
     * which is exactly the hole H5 closed for {@link HttpDocumentLoader} and H4 closed for the
     * subject-document fetch, on the one path neither of them covered.
     *
     * <p>Refused rather than re-checked per hop, as {@link HttpDocumentLoader} does: an OpenID
     * provider's discovery document and JWKS are published at addresses it controls and advertises,
     * so a redirect there is not a case worth supporting.
     */
    private static final com.nimbusds.oauth2.sdk.http.HTTPRequestConfigurator DISCOVERY_REQUEST = request -> {
        request.setConnectTimeout(DISCOVERY_CONNECT_TIMEOUT_MS);
        request.setReadTimeout(DISCOVERY_READ_TIMEOUT_MS);
        request.setFollowRedirects(false);
    };

    /** Size- and time-bounded JWKS retrieval that does not follow redirects. See {@link #DISCOVERY_REQUEST}. */
    private static final com.nimbusds.jose.util.ResourceRetriever JWKS_RETRIEVER =
            new com.nimbusds.jose.util.DefaultResourceRetriever(
                    DISCOVERY_CONNECT_TIMEOUT_MS, DISCOVERY_READ_TIMEOUT_MS, MAX_JWKS_BYTES) {
                @Override
                protected java.net.HttpURLConnection openConnection(URL url) throws java.io.IOException {
                    java.net.HttpURLConnection connection = super.openConnection(url);
                    connection.setInstanceFollowRedirects(false);
                    return connection;
                }
            };
}
