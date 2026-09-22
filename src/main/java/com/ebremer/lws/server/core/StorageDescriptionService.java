package com.ebremer.lws.server.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.DCTerms;
import org.apache.jena.vocabulary.RDF;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.vocab.CID;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Builds the storage description resource: a W3C controlled identifier document, extended with the
 * LWS vocabulary, that describes the storage, its services and its capabilities (lws10-core,
 * Storage Description Resource).
 *
 * <p><b>The storage is the subject, and its URI is the document's own.</b> The description's
 * {@code id} is the canonical URI of the storage, which is also the canonical URL of the document
 * (CID 1.0). On this server that URI is the root container's, which lws10-core permits ("Storage
 * MAY function as a root container"), so {@code /} answers with this document when it is asked for
 * {@code application/lws+cid} — or for nothing in particular — and with the root container listing
 * when it is asked for a container representation. It is still served at
 * {@code <system-prefix>/storage-description} as well, for clients that learned that address.
 *
 * <p><b>Services.</b> A {@code StorageRoot} service naming the root container is mandatory; the
 * notification, type-index, type-search, access-request, access-grant and (optional) SPARQL
 * services follow it. Each is a map with a {@code type} and a {@code serviceEndpoint}.
 *
 * <p><b>Verification methods.</b> Every key this storage signs with is published here as a
 * {@code JsonWebKey} verification method referenced from {@code authentication}, as the webhook
 * notification suite requires: a subscriber verifying a delivery strips the fragment from the
 * signature's {@code keyid}, dereferences what is left — this document — and finds the key by
 * {@code id}.
 *
 * <p><b>One document, several renderings.</b> {@link #buildJson()} is the canonical form and
 * {@link #buildModel()} is derived from it by {@link #toModel}, using the term mappings of the CID
 * context for the CID terms and the LWS namespace for the rest. They used to be written out
 * separately and had drifted apart (finding M22), and {@link #etagBase()} — a hash of the JSON — is
 * a valid validator for every rendering only because they cannot.
 *
 * @author Erich Bremer
 */
public final class StorageDescriptionService {

    /** W3C SPARQL 1.1 Service Description {@code Service} class — the standard type for a SPARQL endpoint. */
    private static final String SPARQL_SERVICE = "http://www.w3.org/ns/sparql-service-description#Service";

    // Capability type identifiers. A capability is an object with a required `type` plus
    // feature-specific fields. The spec's own examples use placeholder URLs because these feature
    // types are not minted in the LWS vocabulary, so the LWS-defined features are identified under
    // the LWS namespace and the digest feature by its defining RFC.
    private static final String PATCH_SUPPORT = "https://www.w3.org/ns/lws#PatchSupport";
    private static final String CONTENT_NEGOTIATION = "https://www.w3.org/ns/lws#ContentNegotiation";
    private static final String DIGEST_FIELDS = "https://www.rfc-editor.org/info/rfc9530";

    /** The specifications this server implements, advertised as type-only capabilities. */
    private static final String CORE = "https://w3c.github.io/lws-protocol/lws10-core/";
    private static final String ACCESS_REQUESTS = CORE + "#access-requests-and-grants";
    private static final String NOTIFICATIONS_WEBHOOK =
            "https://w3c.github.io/lws-protocol/lws10-notifications-webhook/";
    private static final String INDEX = "https://w3c.github.io/lws-protocol/lws10-index/";

    /**
     * The authentication suites this server accepts, as capability URLs.
     *
     * <p>The self-signed {@code did:key} suite is not among them: it was discontinued on
     * 18 September 2026 in favour of the self-signed controlled identifier suite, which now covers
     * {@code did:key} and {@code did:web} subjects. SAML is advertised only when an IdP certificate
     * is configured, because until then it can verify nothing.
     */
    private static final String AUTHN_OPENID = "https://w3c.github.io/lws-protocol/lws10-authn-openid/";
    private static final String AUTHN_SSI_CID = "https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/";
    private static final String AUTHN_SAML = "https://w3c.github.io/lws-protocol/lws10-authn-saml/";

    /** The RDF serialisations this storage can read and write (for the ContentNegotiation capability). */
    private static final List<String> RDF_MEDIA_TYPES = List.of(
            RdfFormats.TURTLE, RdfFormats.JSONLD, RdfFormats.NTRIPLES, RdfFormats.RDFXML, RdfFormats.TRIG);

    /**
     * A key this storage signs with, as it is published: the verification method's fragment and
     * the public JWK. The method's {@code id} is the storage URI with that fragment.
     */
    public record VerificationKey(String fragment, JsonObject publicJwk) {
    }

    /** Terms the CID v1 context defines, and the IRIs it maps them to. */
    private static final Map<String, String> CID_TERMS = Map.of(
            "service", CID.service.getURI(),
            "serviceEndpoint", CID.serviceEndpoint.getURI(),
            "verificationMethod", CID.verificationMethod.getURI(),
            "authentication", CID.authentication.getURI(),
            "controller", CID.controller.getURI(),
            "publicKeyJwk", CID.publicKeyJwk.getURI());

    /** CID and Dublin Core terms whose string values are IRIs ({@code "@type": "@id"}). */
    private static final Set<String> IRI_VALUED =
            Set.of("serviceEndpoint", "authentication", "controller", "conformsTo", "subscriptionType");

    /** Types the CID context defines; every other bare type term is in the LWS namespace. */
    private static final Map<String, String> CID_TYPES =
            Map.of("JsonWebKey", CID.JsonWebKey.getURI(), "Multikey", CID.Multikey.getURI());

    /** Keys handled structurally by {@link #toModel} rather than emitted as predicates. */
    private static final Set<String> STRUCTURAL = Set.of("@context", "id", "type");

    private final LwsConfiguration config;
    private final List<VerificationKey> keys;
    private final JsonObject document;
    private final String etagBase;

    /** A description that publishes no verification method. */
    public StorageDescriptionService(LwsConfiguration config) {
        this(config, List.of());
    }

    public StorageDescriptionService(LwsConfiguration config, List<VerificationKey> keys) {
        this.config = config;
        this.keys = List.copyOf(keys);
        this.document = buildDocument();
        // Computed once: every input is a final configuration field or a key loaded at startup, so
        // the description cannot change while the process lives. Nothing here reads a clock, a
        // request or the store.
        this.etagBase = Etags.sha16(document.toString());
    }

    /**
     * A validator for the storage description, stable for the life of the process.
     *
     * <p>It used to be {@code Etags.forModel(buildModel())}, computed per request over a model whose
     * service and capability nodes are blank, so two calls on identical content produced different
     * tags and a conditional {@code GET} on discovery could never return {@code 304} (finding M22).
     */
    public String etagBase() {
        return etagBase;
    }

    /** The canonical storage description, as {@code application/lws+cid}. */
    public String buildJson() {
        return document.toString();
    }

    /** The canonical storage description as a JSON object. */
    public JsonObject document() {
        return document;
    }

    /** The same description as RDF, derived from {@link #buildJson()} so the two cannot disagree. */
    public Model buildModel() {
        Model m = ModelFactory.createDefaultModel();
        m.setNsPrefix(LWS.PREFIX, LWS.NS);
        m.setNsPrefix("sec", CID.SEC);
        m.setNsPrefix("did", CID.DID);
        m.setNsPrefix("dcterms", DCTerms.getURI());
        toModel(m, document);
        return m;
    }

    /** The {@code id} of the verification method publishing {@code fragment}. */
    public String verificationMethodId(String fragment) {
        return config.storageIri() + "#" + fragment;
    }

    // ----- the one document every rendering comes from -----

    private JsonObject buildDocument() {
        String storage = config.storageIri();

        JsonArrayBuilder services = Json.createArrayBuilder();
        // Mandatory, and first: the entry point of the containment hierarchy.
        services.add(jsonService("StorageRoot", config.storageRootIri()));
        services.add(jsonService("NotificationService", config.subscriptionsEndpointIri())
                .add("subscriptionType", Json.createArrayBuilder().add("WebhookSubscription")));
        if (config.searchIndexEnabled()) {
            services.add(jsonService("TypeIndexService", config.typeIndexEndpointIri()));
            services.add(jsonService("TypeSearchService", config.typeSearchEndpointIri()));
        }
        if (config.accessRequestsEnabled()) {
            services.add(jsonService("AccessRequestService", config.accessRequestsEndpointIri())
                    .add("conformsTo", Json.createArrayBuilder().add(LWS.ACCESS_PROFILE)));
            services.add(jsonService("AccessGrantService", config.accessGrantsEndpointIri())
                    .add("conformsTo", Json.createArrayBuilder().add(LWS.ACCESS_PROFILE)));
        }
        if (config.sparqlEndpointEnabled()) {
            services.add(jsonService(SPARQL_SERVICE, config.sparqlEndpointAdvertisedUrl()));
        }

        JsonArrayBuilder capabilities = Json.createArrayBuilder();
        for (JsonObject capability : capabilities()) {
            capabilities.add(capability);
        }

        JsonObjectBuilder doc = Json.createObjectBuilder()
                .add("@context", Json.createArrayBuilder().add(CID.CONTEXT).add(LWS.JSON_CONTEXT))
                .add("id", storage)
                .add("type", "Storage");
        if (!keys.isEmpty()) {
            JsonArrayBuilder methods = Json.createArrayBuilder();
            JsonArrayBuilder authentication = Json.createArrayBuilder();
            for (VerificationKey key : keys) {
                String id = verificationMethodId(key.fragment());
                methods.add(Json.createObjectBuilder()
                        .add("id", id)
                        .add("type", "JsonWebKey")
                        .add("controller", storage)
                        .add("publicKeyJwk", key.publicJwk()));
                authentication.add(id);
            }
            doc.add("verificationMethod", methods).add("authentication", authentication);
        }
        return doc.add("capability", capabilities)
                .add("service", services)
                .build();
    }

    /**
     * The capability objects advertised on the storage (lws10-core, Storage Capabilities): the
     * specifications this server implements (type only), {@code PatchSupport} — which PATCH formats
     * each target format accepts, keyed {@code format} as in the core's own example —, one
     * {@code ContentNegotiation} per RDF source format, and the RFC 9530 digest algorithms.
     */
    private List<JsonObject> capabilities() {
        List<JsonObject> caps = new ArrayList<>();
        caps.add(typeOnly(CORE));
        caps.add(typeOnly(NOTIFICATIONS_WEBHOOK));
        caps.add(typeOnly(AUTHN_OPENID));
        caps.add(typeOnly(AUTHN_SSI_CID));
        if (config.samlEnabled()) {
            caps.add(typeOnly(AUTHN_SAML));
        }
        if (config.searchIndexEnabled()) {
            caps.add(typeOnly(INDEX));
        }
        if (config.accessRequestsEnabled()) {
            caps.add(typeOnly(ACCESS_REQUESTS));
        }

        JsonObjectBuilder patchMap = Json.createObjectBuilder();
        // SPARQL Update only for RDF: JSON Merge Patch is not defined over RDF and is refused with
        // 415 (finding H21). A capability document that advertises an operation the server rejects
        // is worse than one that omits it — it is what a client reads to decide what to send.
        for (String rdf : RDF_MEDIA_TYPES) {
            patchMap.add(rdf, arr("application/sparql-update"));
        }
        patchMap.add("application/json", arr("application/merge-patch+json", "application/json-patch+json"));
        patchMap.add("application/linkset+json",
                arr("application/merge-patch+json", "application/json-patch+json"));
        caps.add(Json.createObjectBuilder().add("type", PATCH_SUPPORT).add("format", patchMap).build());

        // ContentNegotiation, one per source format as in the core's example: an RDF resource stored
        // in any supported serialisation can be read back in any of the others.
        for (String source : RDF_MEDIA_TYPES) {
            List<String> targets = RDF_MEDIA_TYPES.stream().filter(t -> !t.equals(source)).toList();
            caps.add(Json.createObjectBuilder()
                    .add("type", CONTENT_NEGOTIATION)
                    .add("source", source)
                    .add("target", arr(targets))
                    .build());
        }

        caps.add(Json.createObjectBuilder()
                .add("type", DIGEST_FIELDS)
                .add("algorithm", arr("sha-256", "sha-512"))
                .build());
        return caps;
    }

    // ----- JSON-LD -> RDF, over the CID and LWS contexts' term mappings -----

    /**
     * Interpret one node of the description as RDF and return the node it became.
     *
     * <p>{@code id} is the node, {@code type} is {@code rdf:type}, {@code @context} is not data. A
     * CID term becomes the IRI the CID context maps it to, {@code conformsTo} is Dublin Core's, and
     * every other key is the LWS term of that name. A nested object is a node of its own, except a
     * {@code publicKeyJwk} — {@code "@type": "@json"} in the CID context — and a capability's
     * feature map, which are JSON literals. An array is the key repeated.
     */
    private static Resource toModel(Model m, JsonObject node) {
        String id = stringOf(node.get("id"));
        Resource subject = id == null ? m.createResource() : m.createResource(id);
        for (String term : stringsOf(node.get("type"))) {
            subject.addProperty(RDF.type, m.createResource(expandType(term)));
        }
        for (Map.Entry<String, JsonValue> entry : node.entrySet()) {
            String key = entry.getKey();
            if (STRUCTURAL.contains(key)) {
                continue;
            }
            String predicate = predicateFor(key);
            for (RDFNode object : objectsOf(m, key, entry.getValue())) {
                subject.addProperty(m.createProperty(predicate), object);
            }
        }
        return subject;
    }

    private static String predicateFor(String key) {
        if (CID_TERMS.containsKey(key)) {
            return CID_TERMS.get(key);
        }
        if (key.equals("conformsTo")) {
            return DCTerms.conformsTo.getURI();
        }
        return key.contains(":") ? key : LWS.NS + key;
    }

    private static List<RDFNode> objectsOf(Model m, String key, JsonValue value) {
        List<RDFNode> out = new ArrayList<>();
        switch (value.getValueType()) {
            case ARRAY -> value.asJsonArray().forEach(v -> out.addAll(objectsOf(m, key, v)));
            case OBJECT -> {
                boolean node = !key.equals("publicKeyJwk") && value.asJsonObject().containsKey("type");
                out.add(node ? toModel(m, value.asJsonObject())
                        : m.createTypedLiteral(value.toString(), CID.RDF_JSON));
            }
            case STRING -> {
                String s = ((JsonString) value).getString();
                out.add(IRI_VALUED.contains(key) ? m.createResource(expandType(s)) : m.createLiteral(s));
            }
            case NUMBER, TRUE, FALSE -> out.add(m.createLiteral(value.toString()));
            default -> { /* null: no statement */ }
        }
        return out;
    }

    /** A bare type term is a CID type or an LWS one; anything already absolute stays as it is. */
    private static String expandType(String term) {
        if (term.contains(":")) {
            return term;
        }
        return CID_TYPES.getOrDefault(term, LWS.NS + term);
    }

    private static String stringOf(JsonValue value) {
        return value != null && value.getValueType() == JsonValue.ValueType.STRING
                ? ((JsonString) value).getString() : null;
    }

    private static List<String> stringsOf(JsonValue value) {
        List<String> out = new ArrayList<>();
        if (value == null) {
            return out;
        }
        if (value.getValueType() == JsonValue.ValueType.ARRAY) {
            for (JsonValue v : value.asJsonArray()) {
                if (v.getValueType() == JsonValue.ValueType.STRING) {
                    out.add(((JsonString) v).getString());
                }
            }
        } else if (value.getValueType() == JsonValue.ValueType.STRING) {
            out.add(((JsonString) value).getString());
        }
        return out;
    }

    private static JsonObject typeOnly(String type) {
        return Json.createObjectBuilder().add("type", type).build();
    }

    private static JsonArrayBuilder arr(String... values) {
        JsonArrayBuilder b = Json.createArrayBuilder();
        for (String v : values) {
            b.add(v);
        }
        return b;
    }

    private static JsonArrayBuilder arr(List<String> values) {
        JsonArrayBuilder b = Json.createArrayBuilder();
        values.forEach(b::add);
        return b;
    }

    private static JsonObjectBuilder jsonService(String type, String endpointIri) {
        return Json.createObjectBuilder().add("type", type).add("serviceEndpoint", endpointIri);
    }

    /** The advertised capability types, for tests and tooling. */
    public List<String> capabilityTypes() {
        List<String> types = new ArrayList<>();
        JsonArray caps = document.getJsonArray("capability");
        for (JsonValue v : caps) {
            types.add(v.asJsonObject().getString("type", null));
        }
        return types;
    }

    /** The advertised service types, in document order, for tests and tooling. */
    public List<String> serviceTypes() {
        List<String> types = new ArrayList<>();
        for (JsonValue v : document.getJsonArray("service")) {
            types.add(v.asJsonObject().getString("type", null));
        }
        return types;
    }
}
