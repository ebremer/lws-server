package com.ebremer.lws.server.auth;

import java.io.StringReader;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
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
 * Validates an LWS self-signed controlled identifier (SSI-CID) authentication credential, per
 * <a href="https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/">LWS 1.0 Authentication Suite:
 * Self-signed Identity using Controlled Identifiers</a>.
 *
 * <p>The credential is a JWT, not signed with {@code none}, whose {@code sub}, {@code iss} and
 * {@code client_id} are one URI, and which carries {@code exp} and {@code iat}. The verifier
 * dereferences the subject to its controlled identifier document, whose {@code id} must be the
 * subject, and uses the JWT's {@code kid} to retrieve a verification method from it (CID 1.0 §3.3):
 *
 * <ul>
 *   <li>only methods the {@code authentication} verification relationship names count — embedded in
 *       it, or referenced from it and defined elsewhere in the same document. A key listed under
 *       {@code verificationMethod} alone is not one the subject authenticates with (CID 1.0 §2.3);</li>
 *   <li>a method must be controlled by the subject and live in the subject's document;</li>
 *   <li>a {@code JsonWebKey} carries a {@code publicKeyJwk} with no private members, a
 *       {@code Multikey} a {@code publicKeyMultibase} — the two types CID 1.0 defines. Their
 *       predecessors in the Security Vocabulary, {@code JsonWebKey2020} and
 *       {@code Ed25519VerificationKey2020}, carry the same key material in the same members and
 *       are still common in DID documents, so they are read the same way;</li>
 *   <li>a method past its {@code revoked} or {@code expires} time cannot be used.</li>
 * </ul>
 *
 * <p><b>Subjects.</b> An HTTPS subject is fetched through the policy-checked {@link DocumentLoader}.
 * A DID subject is resolved by its method (the suite's note on DID 1.1): {@code did:key} locally,
 * with nothing to fetch, and {@code did:web} from the HTTPS URL the method derives, through the same
 * loader. This is what replaces the discontinued self-signed {@code did:key} suite, which this suite
 * "subsumes ... by specifying a generalization of the mechanism". Any other DID method is refused.
 *
 * @author Erich Bremer
 */
public final class SsiCidValidator implements CredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(SsiCidValidator.class);

    /** Total characters of cached subject documents; a weight, not a count, bounds the heap. */
    private static final long DOCUMENT_CACHE_CHARS = 8L * 1024 * 1024;

    /** JWK members of the private information class (RFC 7517/7518), which CID 1.0 §2.2.3 forbids. */
    private static final Set<String> PRIVATE_JWK_MEMBERS = Set.of("d", "p", "q", "dp", "dq", "qi", "oth", "k");

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

    /** A verification method the subject may authenticate with, as read from its document. */
    record VerificationMethod(String id, JWK jwk, Instant revoked, Instant expires) {

        /** Why this method may not be used at {@code now}, or {@code null} if it may. */
        String inactiveReason(Instant now) {
            if (revoked != null && !now.isBefore(revoked)) {
                return "was revoked at " + revoked;
            }
            if (expires != null && !now.isBefore(expires)) {
                return "expired at " + expires;
            }
            return null;
        }
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
            if (!audience.permits(claims)) {
                log.debug("ssi-cid credential: aud does not name this storage");
                return Optional.empty();
            }
            String kid = jwt.getHeader().getKeyID();
            if (kid == null || kid.isBlank()) {
                log.debug("ssi-cid credential: JWT has no kid");
                return Optional.empty();
            }
            // Checked before the subject is dereferenced: an expired or over-long credential must not
            // be able to drive an outbound fetch. `iat` is required by the suite, not just bounded.
            if (claims.getIssueTime() == null || !JwsSupport.temporalClaimsValid(claims, maxLifetimeMs)) {
                log.debug("ssi-cid credential: missing iat or exp, expired, post-dated, or lifetime too long");
                return Optional.empty();
            }
            JsonObject doc = subjectDocument(sub);
            if (doc == null) {
                log.debug("ssi-cid credential: could not resolve subject {}", sub);
                return Optional.empty();
            }
            List<VerificationMethod> methods = collect(doc, sub);
            VerificationMethod method = selectByKid(methods, kid);
            if (method == null) {
                log.debug("ssi-cid credential: no authentication method of {} matches kid {}", sub, kid);
                return Optional.empty();
            }
            String inactive = method.inactiveReason(Instant.now());
            if (inactive != null) {
                log.debug("ssi-cid credential: verification method {} {}", method.id(), inactive);
                return Optional.empty();
            }
            if (!JwsSupport.verify(jwt, method.jwk())) {
                log.debug("ssi-cid credential: signature does not verify");
                return Optional.empty();
            }
            return Optional.of(new LwsPrincipal(sub, iss, clientId));
        } catch (Exception | StackOverflowError e) {
            // StackOverflowError as well as Exception: the nesting guard is the control, and this is
            // the backstop for any route into a parser that it does not cover.
            log.debug("ssi-cid validation failed: {}", e.toString());
            return Optional.empty();
        }
    }

    // ----- resolution -----

    /**
     * The subject's controlled identifier (or DID) document, or {@code null} if it cannot be had:
     * generated for a {@code did:key}, fetched for a {@code did:web} or an HTTPS subject.
     */
    private JsonObject subjectDocument(String sub) {
        if (Dids.isDid(sub)) {
            String method;
            try {
                method = Dids.methodOf(sub);
            } catch (IllegalArgumentException e) {
                log.debug("ssi-cid credential: {} is not a valid DID", sub);
                return null;
            }
            switch (method) {
                case Dids.KEY -> {
                    try {
                        return Dids.didKeyDocument(sub);
                    } catch (IllegalArgumentException e) {
                        log.debug("ssi-cid credential: unusable did:key: {}", e.getMessage());
                        return null;
                    }
                }
                case Dids.WEB -> {
                    String url;
                    try {
                        url = Dids.didWebUrl(sub);
                    } catch (IllegalArgumentException e) {
                        log.debug("ssi-cid credential: invalid did:web: {}", e.getMessage());
                        return null;
                    }
                    return parse(fetch(sub, url));
                }
                default -> {
                    log.debug("ssi-cid credential: did:{} is not a DID method this server resolves {}",
                            method, Dids.SUPPORTED_METHODS);
                    return null;
                }
            }
        }
        return parse(fetch(sub, sub));
    }

    /**
     * The document at {@code url}, from cache when it is there.
     *
     * <p>An SSI-CID credential is presented by an <em>un</em>authenticated client and names its own
     * subject, which this server then dereferences to find the verification key. With no cache and
     * no rate limit that made the storage an unmetered HTTP reflector: one request here produced one
     * outbound request to an address of the caller's choosing (finding M5). The loader bounds each
     * fetch's size and time and applies the outbound-fetch policy; this bounds how many.
     *
     * <p>The cost of caching is that a rotated or revoked verification key stays honoured until the
     * entry expires, which is why the positive TTL is minutes and configurable
     * ({@code lws.ssi-cid.document-cache-seconds}).
     */
    private String fetch(String subject, String url) {
        String cached = documents.getIfPresent(subject);
        if (cached != null) {
            return cached;
        }
        if (documentFailures.getIfPresent(subject) != null) {
            return null;
        }
        String text = loader.load(url);
        if (text == null) {
            documentFailures.put(subject, Boolean.TRUE);
            return null;
        }
        documents.put(subject, text);
        return text;
    }

    /**
     * Parse a fetched document, bounded before parsing: it comes from a URL the credential names, so
     * an unauthenticated client chooses it, and the loader's size cap is no bound on its shape —
     * {@code [} repeated four thousand times is four kilobytes and overflows the parser's stack.
     */
    private static JsonObject parse(String text) {
        if (text == null) {
            return null;
        }
        JsonLimits.requireBoundedNesting(text, JsonLimits.MAX_NESTING_DEPTH);
        try (JsonReader reader = Json.createReader(new StringReader(text))) {
            return reader.readObject();
        }
    }

    // ----- verification methods (CID 1.0 §3.3) -----

    /**
     * The verification methods a document's {@code authentication} relationship names.
     *
     * <p>The document's {@code id} must be the subject. A relationship entry is either a method
     * (embedded) or a reference to one, resolved against the document's {@code id} and looked up in
     * this document only; a reference into another document is not followed. A method is kept only
     * if it is controlled by the subject, lives in the subject's document, and is a
     * {@code JsonWebKey} or {@code Multikey} this server can use.
     *
     * @return the usable methods, possibly none; none as well when the document's {@code id} is not
     *         the subject
     */
    static List<VerificationMethod> collect(JsonObject doc, String sub) {
        List<VerificationMethod> out = new ArrayList<>();
        String id = string(doc, "id");
        if (id == null || !id.equals(sub)) {
            log.debug("ssi-cid credential: document id {} is not the subject {}", id, sub);
            return out;
        }
        JsonValue authentication = doc.get("authentication");
        if (authentication == null) {
            return out;
        }
        List<JsonValue> entries = authentication.getValueType() == JsonValue.ValueType.ARRAY
                ? authentication.asJsonArray() : List.of(authentication);
        Set<String> seen = new HashSet<>();
        for (JsonValue entry : entries) {
            JsonObject method = null;
            if (entry.getValueType() == JsonValue.ValueType.STRING) {
                String reference = resolveReference(((JsonString) entry).getString(), id);
                method = reference == null ? null : findById(doc, reference, id);
            } else if (entry.getValueType() == JsonValue.ValueType.OBJECT) {
                method = entry.asJsonObject();
            }
            if (method == null) {
                continue;
            }
            toVerificationMethod(method, sub, id).ifPresent(vm -> {
                if (vm.id() == null || seen.add(vm.id())) {
                    out.add(vm);
                }
            });
        }
        return out;
    }

    private static Optional<VerificationMethod> toVerificationMethod(JsonObject method, String sub, String base) {
        String type = string(method, "type");
        String methodId = resolveReference(string(method, "id"), base);
        String controller = resolveReference(string(method, "controller"), base);
        if (!sub.equals(controller) || !inSubjectsDocument(methodId, sub)) {
            return Optional.empty();
        }
        Instant revoked;
        Instant expires;
        try {
            revoked = dateTimeStamp(string(method, "revoked"));
            expires = dateTimeStamp(string(method, "expires"));
        } catch (DateTimeParseException malformed) {
            // An unreadable revocation date is not evidence that the key was never revoked.
            return Optional.empty();
        }
        try {
            if ("JsonWebKey".equals(type) || "JsonWebKey2020".equals(type)) {
                JsonValue jwk = method.get("publicKeyJwk");
                if (jwk == null || jwk.getValueType() != JsonValue.ValueType.OBJECT) {
                    return Optional.empty();
                }
                for (String member : PRIVATE_JWK_MEMBERS) {
                    if (jwk.asJsonObject().containsKey(member)) {
                        log.debug("ssi-cid: skipping {}: its publicKeyJwk carries private member {}", methodId, member);
                        return Optional.empty();
                    }
                }
                return Optional.of(new VerificationMethod(methodId, JWK.parse(jwk.toString()), revoked, expires));
            }
            if ("Multikey".equals(type) || "Ed25519VerificationKey2020".equals(type)) {
                String multibase = string(method, "publicKeyMultibase");
                return multibase == null ? Optional.empty()
                        : Optional.of(new VerificationMethod(methodId, Multikey.decode(multibase).jwk(), revoked,
                                expires));
            }
        } catch (java.text.ParseException | IllegalArgumentException unusable) {
            log.debug("ssi-cid: skipping verification method {}: {}", methodId, unusable.getMessage());
        }
        return Optional.empty();
    }

    /**
     * The method the JWT's {@code kid} names: by the method's full identifier first (CID 1.0 §3.3
     * retrieves by it, and it is the usual {@code kid} for a DID), then by the JWK's own
     * {@code kid}, then by the fragment of the method's identifier, raw or percent-decoded, a
     * leading {@code #} on the {@code kid} allowed. There is no fallback to "the only key": the
     * credential says which key signed it, and honouring that is the point of the check.
     */
    static VerificationMethod selectByKid(List<VerificationMethod> methods, String kid) {
        if (methods.isEmpty() || kid == null || kid.isBlank()) {
            return null;
        }
        for (VerificationMethod method : methods) {
            if (kid.equals(method.id())) {
                return method;
            }
        }
        for (VerificationMethod method : methods) {
            if (kid.equals(method.jwk().getKeyID())) {
                return method;
            }
        }
        String wanted = kid.startsWith("#") ? kid.substring(1) : kid;
        for (VerificationMethod method : methods) {
            String id = method.id();
            int hash = id == null ? -1 : id.lastIndexOf('#');
            if (hash < 0) {
                continue;
            }
            String fragment = id.substring(hash + 1);
            if (wanted.equals(fragment) || wanted.equals(decodeFragment(fragment))) {
                return method;
            }
        }
        return null;
    }

    // ----- helpers -----

    /**
     * Resolve a reference found in a document against the document's {@code id}: an absolute URL or
     * DID URL as it is, a fragment appended to the id (DID 1.1 §3.2.1's relative DID URL), and any
     * other relative reference by RFC 3986 against a hierarchical id.
     */
    static String resolveReference(String reference, String base) {
        if (reference == null || reference.isBlank()) {
            return null;
        }
        if (reference.matches("^[A-Za-z][A-Za-z0-9+.-]*:.*")) {
            return reference;
        }
        if (base == null) {
            return null;
        }
        String document = documentOf(base);
        if (reference.startsWith("#")) {
            return document + reference;
        }
        try {
            URI uri = new URI(document);
            return uri.isOpaque() ? null : uri.resolve(reference).toString();
        } catch (java.net.URISyntaxException | IllegalArgumentException invalid) {
            return null;
        }
    }

    /**
     * True iff a method identifier, when there is one, names the subject's own document. Document is
     * compared with document, so a subject with a fragment — a WebID such as
     * {@code https://alice.example/card#me} — still owns {@code https://alice.example/card#key-1}.
     */
    private static boolean inSubjectsDocument(String methodId, String sub) {
        return methodId == null || documentOf(methodId).equals(documentOf(sub));
    }

    private static String documentOf(String identifier) {
        int hash = identifier.indexOf('#');
        return hash >= 0 ? identifier.substring(0, hash) : identifier;
    }

    /** The first object anywhere in {@code value} whose {@code id} resolves to {@code reference}. */
    private static JsonObject findById(JsonValue value, String reference, String base) {
        if (value == null) {
            return null;
        }
        if (value.getValueType() == JsonValue.ValueType.OBJECT) {
            JsonObject object = value.asJsonObject();
            String id = string(object, "id");
            if (id != null && reference.equals(resolveReference(id, base))) {
                return object;
            }
            for (Map.Entry<String, JsonValue> child : object.entrySet()) {
                JsonObject found = findById(child.getValue(), reference, base);
                if (found != null) {
                    return found;
                }
            }
        } else if (value.getValueType() == JsonValue.ValueType.ARRAY) {
            for (JsonValue child : value.asJsonArray()) {
                JsonObject found = findById(child, reference, base);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static String string(JsonObject object, String name) {
        JsonValue v = object.get(name);
        return v != null && v.getValueType() == JsonValue.ValueType.STRING ? ((JsonString) v).getString() : null;
    }

    /** An {@code xsd:dateTimeStamp} (a date-time with a time zone), or {@code null} if absent. */
    private static Instant dateTimeStamp(String value) {
        return value == null ? null : OffsetDateTime.parse(value.trim()).toInstant();
    }

    private static String decodeFragment(String fragment) {
        try {
            return URLDecoder.decode(fragment.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return fragment;
        }
    }
}
