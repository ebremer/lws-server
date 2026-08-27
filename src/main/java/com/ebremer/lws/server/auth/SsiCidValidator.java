package com.ebremer.lws.server.auth;

import java.io.StringReader;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.core.JsonLimits;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Validates an LWS Self-signed Controlled Identifier (SSI-CID) authentication credential, per
 * <a href="https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/">LWS Authentication: Self-signed
 * Controlled Identifier</a>. The credential is a signed JWT whose {@code sub}, {@code iss} and
 * {@code client_id} are the same controlled-identifier URL; the JWT header {@code kid} selects a
 * {@code verificationMethod} (carrying a {@code publicKeyJwk}) in the dereferenced controlled
 * identifier document, which provides the verification key.
 *
 * @author Erich Bremer
 */
public final class SsiCidValidator implements CredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(SsiCidValidator.class);

    /** Total characters of cached subject documents; a weight, not a count, bounds the heap. */
    private static final long DOCUMENT_CACHE_CHARS = 8L * 1024 * 1024;

    private final DocumentLoader loader;
    private final AudiencePolicy audience;
    private final long maxLifetimeMs;
    // Subject documents, positively and negatively cached (finding M5).
    private final Cache<String, String> documents;
    private final Cache<String, Boolean> documentFailures;

    /**
     * @param loader        the policy-checked, size-capped document loader
     * @param audience      audience policy; an SSI-CID credential is self-minted, so without one a
     *                      token addressed to another storage would authenticate here
     * @param maxLifetimeMs maximum accepted token lifetime, or {@code <= 0} for unlimited
     */
    public SsiCidValidator(DocumentLoader loader, AudiencePolicy audience, long maxLifetimeMs) {
        this(loader, audience, maxLifetimeMs, 300, 30);
    }

    /**
     * @param documentCacheSeconds  how long a fetched subject document is reused
     * @param documentFailureSeconds how long a subject that could not be fetched is left alone
     */
    public SsiCidValidator(DocumentLoader loader, AudiencePolicy audience, long maxLifetimeMs,
            long documentCacheSeconds, long documentFailureSeconds) {
        this.loader = loader;
        this.audience = audience;
        this.maxLifetimeMs = maxLifetimeMs;
        this.documents = Caffeine.newBuilder()
                .expireAfterWrite(Math.max(1, documentCacheSeconds), TimeUnit.SECONDS)
                .maximumWeight(DOCUMENT_CACHE_CHARS)
                .<String, String>weigher((url, doc) -> doc.length())
                .build();
        this.documentFailures = Caffeine.newBuilder()
                .expireAfterWrite(Math.max(1, documentFailureSeconds), TimeUnit.SECONDS)
                .maximumSize(10_000)
                .build();
    }

    /**
     * The subject's controlled identifier document, from cache when it is there.
     *
     * <p>An SSI-CID credential is presented by an <em>un</em>authenticated client and names its own
     * subject URL, which this server then dereferences to find the verification key. With no cache
     * and no rate limit that made the storage an unmetered HTTP reflector: one request here produced
     * one outbound request to an address of the caller's choosing, repeatable as fast as the caller
     * could send (finding M5). The loader already bounds each fetch's size and time and applies the
     * outbound-fetch policy; what was missing was a bound on <em>how many</em>.
     *
     * <p>Bounded by total characters rather than entry count, because the entries are documents and
     * a count says nothing about the heap. Failures are remembered separately and much more briefly,
     * so an unreachable subject is not re-fetched per request while a real outage still clears in
     * seconds.
     *
     * <p>The cost of caching is that a rotated or revoked verification key stays honoured until the
     * entry expires. That is why the positive TTL is minutes rather than the hour the JWKS cache
     * uses, and why it is configurable: {@code lws.ssi-cid.document-cache-seconds}.
     */
    private String subjectDocument(String sub) {
        String cached = documents.getIfPresent(sub);
        if (cached != null) {
            return cached;
        }
        if (documentFailures.getIfPresent(sub) != null) {
            return null;
        }
        String docText = loader.load(sub);
        if (docText == null) {
            documentFailures.put(sub, Boolean.TRUE);
            return null;
        }
        documents.put(sub, docText);
        return docText;
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
            if (sub == null || !sub.equals(iss) || !sub.equals(clientId)) {
                return Optional.empty();
            }
            if (sub.startsWith("did:")) {
                return Optional.empty(); // DIDs are handled by their own suite
            }
            if (!audience.permits(claims)) {
                log.debug("ssi-cid credential: aud does not name this storage");
                return Optional.empty();
            }
            String kid = jwt.getHeader().getKeyID();
            if (kid == null) {
                log.debug("ssi-cid credential: JWT has no kid");
                return Optional.empty();
            }
            String docText = subjectDocument(sub);
            if (docText == null) {
                log.debug("ssi-cid credential: could not dereference subject {}", sub);
                return Optional.empty();
            }
            // Bounded before parsing. This document is fetched from a URL the credential itself
            // names, so an UNAUTHENTICATED client chooses it, and the loader's 2 MiB size cap is
            // no bound on its shape: `[` repeated four thousand times is four kilobytes and
            // overflows the parser's stack. A StackOverflowError is an Error, so it escaped the
            // catch(Exception) below, aborted the request with no status, and — measured — can
            // poison the JSON provider's message class for the life of the JVM, after which every
            // later malformed-JSON error anywhere in the server surfaces as NoClassDefFoundError
            // instead of the exception its callers catch.
            JsonLimits.requireBoundedNesting(docText, JsonLimits.MAX_NESTING_DEPTH);
            JsonObject doc;
            try (JsonReader reader = Json.createReader(new StringReader(docText))) {
                doc = reader.readObject();
            }
            if (!sub.equals(doc.getString("id", null))) {
                log.debug("ssi-cid credential: document id does not match subject");
                return Optional.empty();
            }
            JsonObject jwkJson = findPublicKeyJwk(doc, kid, sub);
            if (jwkJson == null) {
                log.debug("ssi-cid credential: no verificationMethod with a publicKeyJwk for kid {}", kid);
                return Optional.empty();
            }
            JWK jwk = JWK.parse(jwkJson.toString());
            if (!JwsSupport.verify(jwt, jwk)) {
                log.debug("ssi-cid credential: signature does not verify");
                return Optional.empty();
            }
            if (!JwsSupport.temporalClaimsValid(claims, maxLifetimeMs)) {
                log.debug("ssi-cid credential: missing/expired exp, post-dated, or lifetime too long");
                return Optional.empty();
            }
            return Optional.of(new LwsPrincipal(sub, iss, clientId));
        } catch (Exception | StackOverflowError e) {
            // StackOverflowError as well as Exception: the guard above is the control, and this is
            // the backstop for any route into a parser that it does not cover.
            log.debug("ssi-cid validation failed: {}", e.toString());
            return Optional.empty();
        }
    }

    private static JsonObject findPublicKeyJwk(JsonObject doc, String kid, String sub) {
        if (!doc.containsKey("verificationMethod")
                || doc.get("verificationMethod").getValueType() != JsonValue.ValueType.ARRAY) {
            return null;
        }
        JsonArray methods = doc.getJsonArray("verificationMethod");
        for (JsonValue value : methods) {
            if (value.getValueType() != JsonValue.ValueType.OBJECT) {
                continue;
            }
            JsonObject vm = value.asJsonObject();
            String id = vm.getString("id", null);
            if (id != null && matchesKid(id, kid, sub)
                    && vm.containsKey("publicKeyJwk")
                    && vm.get("publicKeyJwk").getValueType() == JsonValue.ValueType.OBJECT) {
                return vm.getJsonObject("publicKeyJwk");
            }
        }
        return null;
    }

    private static boolean matchesKid(String vmId, String kid, String sub) {
        if (vmId.equals(kid)) {
            return true;
        }
        String fragment = kid.startsWith("#") ? kid : "#" + kid;
        return vmId.equals(sub + fragment) || vmId.endsWith(fragment);
    }
}
