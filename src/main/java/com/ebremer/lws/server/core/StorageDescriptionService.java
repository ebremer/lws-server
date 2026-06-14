package com.ebremer.lws.server.core;

import java.util.ArrayList;
import java.util.List;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.rdf.model.Literal;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.DCTerms;
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
 * {@code serviceEndpoint} (an {@code xsd:anyURI}, per the vocabulary's stated range):
 * a {@code NotificationService} (with its {@code subscriptionType}s), a {@code StorageDescription}
 * service pointing at this resource (required for discovery), and — when enabled — a
 * {@code TypeIndexService} and a {@code TypeSearchService}.
 *
 * <p>The canonical representation is {@code application/lws+json} ({@link #buildJson()}); the same
 * description is also available as RDF ({@link #buildModel()}) via content negotiation.
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

    /** The RDF serialisations this storage can read and write (for the ContentNegotiation capability). */
    private static final List<String> RDF_MEDIA_TYPES = List.of(
            RdfFormats.TURTLE, RdfFormats.JSONLD, RdfFormats.NTRIPLES, RdfFormats.RDFXML, RdfFormats.TRIG);

    private final LwsConfiguration config;

    public StorageDescriptionService(LwsConfiguration config) {
        this.config = config;
    }

    public Model buildModel() {
        Model m = ModelFactory.createDefaultModel();
        m.setNsPrefix(LWS.PREFIX, LWS.NS);

        Resource root = m.createResource(config.storageRootIri());
        Resource desc = m.createResource(config.storageDescriptionIri());

        root.addProperty(RDF.type, LWS.Storage);
        root.addProperty(LWS.storageDescription, desc);

        desc.addProperty(RDF.type, LWS.StorageDescription);
        desc.addProperty(LWS.storage, root);

        // NotificationService advertisement (required for notification support discovery).
        Resource notifications = m.createResource();
        notifications.addProperty(RDF.type, LWS.NotificationService);
        notifications.addProperty(LWS.serviceEndpoint, endpoint(m, config.subscriptionsEndpointIri()));
        notifications.addProperty(LWS.subscriptionType, LWS.WebhookSubscription);
        root.addProperty(LWS.service, notifications);

        // Type Index / Type Search service advertisement (lws10-searchindex). A storage that
        // supports either service MUST advertise it with a service object carrying serviceEndpoint.
        if (config.searchIndexEnabled()) {
            root.addProperty(LWS.service, service(m, LWS.TypeIndexService, config.typeIndexEndpointIri()));
            root.addProperty(LWS.service, service(m, LWS.TypeSearchService, config.typeSearchEndpointIri()));
        }

        // Access Request / Access Grant services (lws10-core/lws-access-requests), advertising the
        // access profile they conform to.
        if (config.accessRequestsEnabled()) {
            Resource accessRequest = service(m, LWS.AccessRequestService, config.accessRequestsEndpointIri());
            accessRequest.addProperty(DCTerms.conformsTo, m.createResource(LWS.ACCESS_PROFILE));
            root.addProperty(LWS.service, accessRequest);
            Resource accessGrant = service(m, LWS.AccessGrantService, config.accessGrantsEndpointIri());
            accessGrant.addProperty(DCTerms.conformsTo, m.createResource(LWS.ACCESS_PROFILE));
            root.addProperty(LWS.service, accessGrant);
        }

        // Embedded SPARQL endpoint, advertised as a W3C SPARQL Service Description service.
        if (config.sparqlEndpointEnabled()) {
            root.addProperty(LWS.service, service(m, m.createResource(SPARQL_SERVICE),
                    config.sparqlEndpointAdvertisedUrl()));
        }

        // StorageDescription service (required by discovery): its serviceEndpoint is this resource.
        root.addProperty(LWS.service, service(m, LWS.StorageDescription, config.storageDescriptionIri()));

        // Storage capabilities. Each is a node typed with the capability's `type`; the feature-specific
        // detail (PatchSupport's media-type map, etc.) is carried in the canonical lws+json form, since
        // the LWS vocabulary defines no predicates for it.
        for (JsonObject capability : capabilities()) {
            root.addProperty(LWS.capability,
                    m.createResource().addProperty(RDF.type, m.createResource(capability.getString("type"))));
        }
        return m;
    }

    /**
     * The canonical {@code application/lws+json} storage description: a flat JSON-LD document whose
     * primary node is the storage, carrying its capabilities and service objects.
     */
    public String buildJson() {
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
                .add("capability", capabilities)
                .add("service", services)
                .build().toString();
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
        caps.add(typeOnly("https://w3c.github.io/lws-protocol/lws10-authn-openid/"));
        caps.add(typeOnly("https://w3c.github.io/lws-protocol/lws10-notifications/"));
        if (config.searchIndexEnabled()) {
            caps.add(typeOnly("https://w3c.github.io/lws-protocol/lws10-searchindex/"));
        }
        if (config.accessRequestsEnabled()) {
            caps.add(typeOnly("https://w3c.github.io/lws-protocol/lws10-core/#access-requests"));
        }

        // PatchSupport: which PATCH content types are accepted for each target representation.
        JsonObjectBuilder patchMap = Json.createObjectBuilder();
        for (String rdf : RDF_MEDIA_TYPES) {
            patchMap.add(rdf, arr("application/sparql-update", "application/merge-patch+json"));
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

    private static Resource service(Model m, Resource type, String endpointIri) {
        return m.createResource()
                .addProperty(RDF.type, type)
                .addProperty(LWS.serviceEndpoint, endpoint(m, endpointIri));
    }

    private static Literal endpoint(Model m, String uri) {
        return m.createTypedLiteral(uri, XSDDatatype.XSDanyURI);
    }
}
