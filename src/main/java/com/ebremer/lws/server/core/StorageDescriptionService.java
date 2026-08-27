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
import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.rdf.RdfFormats;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Builds the storage description resource: the {@code lws:StorageDescription} that enumerates
 * the storage root and advertises the storage's services and capabilities.
 *
 * <p>Services are advertised on the <strong>storage</strong> itself. In the LWS vocabulary
 * {@code lws:service} (and {@code lws:capability}) has domain {@code lws:Storage}, and the
 * notification and search-index discovery examples both carry the {@code service} array on the
 * node typed {@code Storage}. Each service object carries an {@code rdf:type} and a
 * {@code serviceEndpoint} (an {@code xsd:anyURI}, per the vocabulary's stated range).
 *
 * <p><b>One document, two renderings.</b> {@link #buildJson()} is the canonical
 * {@code application/lws+json} form and {@link #buildModel()} is now <em>derived from it</em>, by
 * {@link #toModel} walking the same object. They used to be written out separately and had drifted
 * apart in two ways an operator could not see: the RDF form emitted a capability node carrying only
 * its {@code rdf:type}, dropping the {@code PatchSupport} media-type map, the negotiable
 * serializations and the digest algorithms entirely; and only the RDF form said anything about the
 * description resource itself. A client that negotiated Turtle got a materially poorer answer than
 * one that took the default, from the endpoint whose whole purpose is telling clients what this
 * server can do.
 *
 * <p>Deriving one from the other is not an invention: an {@code application/lws+json} document
 * <em>is</em> JSON-LD carrying {@link LWS#JSON_CONTEXT}, so its RDF interpretation maps each
 * unprefixed term into the LWS namespace. {@link #toModel} does exactly that walk. It also means
 * {@link #etagBase()} — a hash of the JSON — is a validator for both renderings, which is what makes
 * the storage description conditionally cacheable at all (finding M22).
 *
 * @author Erich Bremer
 */
public final class StorageDescriptionService {

    /** W3C SPARQL 1.1 Service Description {@code Service} class — the standard type for a SPARQL endpoint. */
    private static final String SPARQL_SERVICE = "http://www.w3.org/ns/sparql-service-description#Service";

    // Capability type identifiers. A capability is an object with a required `type` (a URL) plus
    // feature-specific fields. The spec's own discovery example uses placeholder URLs because these
    // feature types are not yet minted in the LWS vocabulary, so we identify the LWS-defined features
    // under the LWS namespace and the digest feature by its defining RFC.
    private static final String PATCH_SUPPORT = "https://www.w3.org/ns/lws#PatchSupport";
    private static final String CONTENT_NEGOTIATION = "https://www.w3.org/ns/lws#ContentNegotiation";
    private static final String DIGEST_FIELDS = "https://www.rfc-editor.org/info/rfc9530";

    /**
     * The authentication suites this server implements, as protocol-module capability URLs.
     *
     * <p>Only {@code OpenID} used to be advertised, though all four are implemented and the README
     * says so. A client reads this document to decide what to present; advertising one suite told it
     * the other three were unavailable. Three of the four need no configuration at all — the
     * credential itself carries everything needed to verify it — so they are advertised
     * unconditionally, which is not the same "unconditionally" the finding objected to. SAML is the
     * exception: it is inert until an IdP certificate is configured, so it is advertised only then.
     */
    private static final String AUTHN_OPENID = "https://w3c.github.io/lws-protocol/lws10-authn-openid/";
    private static final String AUTHN_SSI_CID = "https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/";
    private static final String AUTHN_DID_KEY = "https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/";
    private static final String AUTHN_SAML = "https://w3c.github.io/lws-protocol/lws10-authn-saml/";

    /** The RDF serialisations this storage can read and write (for the ContentNegotiation capability). */
    private static final List<String> RDF_MEDIA_TYPES = List.of(
            RdfFormats.TURTLE, RdfFormats.JSONLD, RdfFormats.NTRIPLES, RdfFormats.RDFXML, RdfFormats.TRIG);

    /**
     * Keys whose string values name a resource rather than carry a label.
     *
     * <p>{@code serviceEndpoint} is the exception to the exception: the LWS vocabulary gives it a
     * stated range of {@code xsd:anyURI}, so it stays a typed literal rather than becoming a node.
     */
    private static final Set<String> IRI_VALUED = Set.of("conformsTo", "storage", "subscriptionType");

    /**
     * Terms the LWS context does <em>not</em> map into its own namespace.
     *
     * <p>{@code conformsTo} is Dublin Core's, and the RDF rendering has always emitted it as such.
     * The context document itself cannot be consulted to confirm the mapping — {@code JsonLdSecurity}
     * refuses remote contexts, which is the point of it — so the safe reading is the one that keeps
     * the well-known term well-known and preserves what this server already published.
     */
    private static final Map<String, String> TERM_IRIS =
            Map.of("conformsTo", org.apache.jena.vocabulary.DCTerms.conformsTo.getURI());

    /** Keys handled structurally by {@link #toModel} rather than emitted as predicates. */
    private static final Set<String> STRUCTURAL = Set.of("@context", "id", "type");

    private final LwsConfiguration config;
    private final JsonObject document;
    private final String etagBase;

    public StorageDescriptionService(LwsConfiguration config) {
        this.config = config;
        this.document = buildDocument();
        // Computed once, in the constructor, exactly as StorageDescriptionServlet's Last-Modified
        // already was: every input is a final configuration field, so the description cannot change
        // while the process lives. Nothing here reads a clock, a request or the store.
        this.etagBase = Etags.sha16(document.toString());
    }

    /**
     * A validator for the storage description, stable for the life of the process.
     *
     * <p>It used to be {@code Etags.forModel(buildModel())}, computed per request over a model whose
     * service and capability nodes are <em>blank</em>. {@code forModel} serializes to N-Triples and
     * sorts the lines, which makes it order-independent but not blank-node-independent: Jena mints a
     * fresh label per model instance, so two calls on identical content produced different tags —
     * measured, {@code 40ec162e5e06c3d7} against {@code d699cc4ca046b387}. A conditional {@code GET}
     * on discovery could therefore never return {@code 304}: every polling client re-transferred the
     * whole document, and a shared cache accumulated one entry per request (finding M22).
     */
    public String etagBase() {
        return etagBase;
    }

    /**
     * The canonical {@code application/lws+json} storage description: a flat JSON-LD document whose
     * primary node is the storage, carrying its capabilities and service objects.
     */
    public String buildJson() {
        return document.toString();
    }

    /** The same description as RDF, derived from {@link #buildJson()} so the two cannot disagree. */
    public Model buildModel() {
        Model m = ModelFactory.createDefaultModel();
        m.setNsPrefix(LWS.PREFIX, LWS.NS);
        toModel(m, document);
        return m;
    }

    // ----- the one document both renderings come from -----

    private JsonObject buildDocument() {
        JsonArrayBuilder services = Json.createArrayBuilder();
        services.add(Json.createObjectBuilder()
                .add("type", "NotificationService")
                .add("serviceEndpoint", config.subscriptionsEndpointIri())
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
        services.add(jsonService("StorageDescription", config.storageDescriptionIri()));

        JsonArrayBuilder capabilities = Json.createArrayBuilder();
        for (JsonObject capability : capabilities()) {
            capabilities.add(capability);
        }

        return Json.createObjectBuilder()
                .add("@context", LWS.JSON_CONTEXT)
                .add("id", config.storageRootIri())
                .add("type", "Storage")
                // The description resource, named and typed here rather than only in the RDF
                // rendering. A nested node, not a second top-level one: the document's primary node
                // is the storage, and clients read `id`/`type` off the top level.
                .add("storageDescription", Json.createObjectBuilder()
                        .add("id", config.storageDescriptionIri())
                        .add("type", "StorageDescription")
                        .add("storage", config.storageRootIri()))
                .add("capability", capabilities)
                .add("service", services)
                .build();
    }

    /**
     * The structured capability objects advertised on the storage (lws10-core Storage Capabilities).
     * Each is a JSON object with a required {@code type} and optional feature-specific fields: the
     * implemented protocol modules (type-only), {@code PatchSupport} (a target-media-type → accepted
     * PATCH formats map), {@code ContentNegotiation} (the interchangeable RDF serialisations), and
     * RFC 9530 digest fields (the supported algorithms).
     */
    private List<JsonObject> capabilities() {
        List<JsonObject> caps = new ArrayList<>();
        caps.add(typeOnly("https://w3c.github.io/lws-protocol/lws10-core/"));
        caps.add(typeOnly("https://w3c.github.io/lws-protocol/lws10-notifications/"));
        // Every authentication suite that is actually usable on this deployment; see the constants.
        caps.add(typeOnly(AUTHN_OPENID));
        caps.add(typeOnly(AUTHN_SSI_CID));
        caps.add(typeOnly(AUTHN_DID_KEY));
        if (config.samlEnabled()) {
            caps.add(typeOnly(AUTHN_SAML));
        }
        if (config.searchIndexEnabled()) {
            caps.add(typeOnly("https://w3c.github.io/lws-protocol/lws10-searchindex/"));
        }
        if (config.accessRequestsEnabled()) {
            caps.add(typeOnly("https://w3c.github.io/lws-protocol/lws10-core/#access-requests"));
        }

        // PatchSupport: which PATCH content types are accepted for each target representation.
        JsonObjectBuilder patchMap = Json.createObjectBuilder();
        // SPARQL Update only: JSON Merge Patch is not defined over RDF and is refused with 415
        // (finding H21). A capability document that advertises an operation the server rejects is
        // worse than one that omits it — it is what a conformance client reads to decide what to send.
        for (String rdf : RDF_MEDIA_TYPES) {
            patchMap.add(rdf, arr("application/sparql-update"));
        }
        patchMap.add("application/json", arr("application/merge-patch+json", "application/json-patch+json"));
        patchMap.add("application/linkset+json",
                arr("application/merge-patch+json", "application/json-patch+json"));
        caps.add(Json.createObjectBuilder().add("type", PATCH_SUPPORT).add("mediaType", patchMap).build());

        // ContentNegotiation: an RDF resource can be served as any supported RDF serialisation
        // (negotiation is symmetric — any supported RDF type in, any supported RDF type out).
        caps.add(Json.createObjectBuilder()
                .add("type", CONTENT_NEGOTIATION)
                .add("source", arr(RDF_MEDIA_TYPES))
                .add("target", arr(RDF_MEDIA_TYPES))
                .build());

        // RFC 9530 digest fields and the algorithms this server produces and verifies.
        caps.add(Json.createObjectBuilder()
                .add("type", DIGEST_FIELDS)
                .add("algorithm", arr("sha-256", "sha-512"))
                .build());
        return caps;
    }

    // ----- JSON-LD -> RDF, over the LWS context's term mapping -----

    /**
     * Interpret one lws+json node as RDF and return the node it became.
     *
     * <p>The rules are the LWS JSON-LD context's: {@code id} is the node, {@code type} is
     * {@code rdf:type}, {@code @context} is not data, and every other key is the term of that name in
     * the LWS namespace. A nested object is a node of its own; an array is the key repeated. A string
     * value is a resource when the key is one that names things ({@link #IRI_VALUED}) and a literal
     * otherwise — except {@code serviceEndpoint}, whose stated range is {@code xsd:anyURI}.
     */
    private static Resource toModel(Model m, JsonObject node) {
        String id = stringOf(node.get("id"));
        Resource subject = id == null ? m.createResource() : m.createResource(id);
        for (String term : stringsOf(node.get("type"))) {
            subject.addProperty(RDF.type, m.createResource(expand(term)));
        }
        for (Map.Entry<String, JsonValue> entry : node.entrySet()) {
            if (STRUCTURAL.contains(entry.getKey())) {
                continue;
            }
            String predicate = TERM_IRIS.getOrDefault(entry.getKey(), LWS.NS + entry.getKey());
            for (RDFNode object : objectsOf(m, entry.getKey(), entry.getValue())) {
                subject.addProperty(m.createProperty(predicate), object);
            }
        }
        return subject;
    }

    private static List<RDFNode> objectsOf(Model m, String term, JsonValue value) {
        List<RDFNode> out = new ArrayList<>();
        switch (value.getValueType()) {
            case ARRAY -> value.asJsonArray().forEach(v -> out.addAll(objectsOf(m, term, v)));
            case OBJECT -> out.add(toModel(m, value.asJsonObject()));
            case STRING -> {
                String s = ((JsonString) value).getString();
                if (term.equals("serviceEndpoint")) {
                    out.add(m.createTypedLiteral(s, XSDDatatype.XSDanyURI));
                } else if (IRI_VALUED.contains(term)) {
                    out.add(m.createResource(expand(s)));
                } else {
                    out.add(m.createLiteral(s));
                }
            }
            case NUMBER, TRUE, FALSE -> out.add(m.createLiteral(value.toString()));
            default -> { /* null: no statement */ }
        }
        return out;
    }

    /** A bare term is in the LWS namespace; anything already absolute stays as it is. */
    private static String expand(String term) {
        return term.contains(":") ? term : LWS.NS + term;
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

    /** The advertised capability type IRIs, for tests and tooling. */
    public List<String> capabilityTypes() {
        List<String> types = new ArrayList<>();
        JsonArray caps = document.getJsonArray("capability");
        for (JsonValue v : caps) {
            types.add(v.asJsonObject().getString("type", null));
        }
        return types;
    }
}
