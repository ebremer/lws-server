package com.ebremer.lws.server.vocab;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

/**
 * The Linked Web Storage vocabulary.
 *
 * <p>Namespace: {@code https://www.w3.org/ns/lws#} as defined by the
 * <a href="https://w3c.github.io/lws-protocol/lws10-vocab/">LWS Vocabulary</a>.
 *
 * @author Erich Bremer
 */
public final class LWS {

    private LWS() {
    }

    /** The RDF namespace IRI for the LWS vocabulary. */
    public static final String NS = "https://www.w3.org/ns/lws#";

    /** The preferred prefix for the LWS namespace. */
    public static final String PREFIX = "lws";

    /** The JSON-LD context IRI for {@code application/lws+json} documents. */
    public static final String JSON_CONTEXT = "https://www.w3.org/ns/lws/v1";

    public static String getURI() {
        return NS;
    }

    private static final Model M = ModelFactory.createDefaultModel();

    private static Resource r(String local) {
        return M.createResource(NS + local);
    }

    private static Property p(String local) {
        return M.createProperty(NS + local);
    }

    // ----- Classes -----
    /** A Linked Web Storage instance. */
    public static final Resource Storage = r("Storage");
    /** A resource that enumerates and describes a storage's root, services and capabilities. */
    public static final Resource StorageDescription = r("StorageDescription");
    /** A resource that contains other resources. */
    public static final Resource Container = r("Container");
    /** A data-bearing resource such as a document, image, or structured data file. */
    public static final Resource DataResource = r("DataResource");
    /** A notification envelope describing an event that occurred on a resource. */
    public static final Resource Notification = r("Notification");
    /** A service through which clients subscribe to resource change notifications. */
    public static final Resource NotificationService = r("NotificationService");
    /** A subscription type that delivers notifications via HTTP POST (webhook). */
    public static final Resource WebhookSubscription = r("WebhookSubscription");
    /** An OpenID Connect identity provider service. */
    public static final Resource OpenIdProvider = r("OpenIdProvider");
    /** A service that enumerates the distinct resource types present in a storage. */
    public static final Resource TypeIndexService = r("TypeIndexService");
    /** A service that returns the resources matching a type/relation filter. */
    public static final Resource TypeSearchService = r("TypeSearchService");
    /** A service through which agents submit access requests. */
    public static final Resource AccessRequestService = r("AccessRequestService");
    /** A service through which a storage controller issues access grants. */
    public static final Resource AccessGrantService = r("AccessGrantService");
    /** An agent's request to perform actions on storage resources. */
    public static final Resource AccessRequest = r("AccessRequest");
    /** A storage controller's grant of the ability to perform actions on storage resources. */
    public static final Resource AccessGrant = r("AccessGrant");

    /** The ODRL-based access profile defined by the LWS access-requests specification. */
    public static final String ACCESS_PROFILE = NS + "AccessProfile";
    /** The FOAF Agent class IRI, used as the {@code assignee} for public access. */
    public static final String FOAF_AGENT = "http://xmlns.com/foaf/0.1/Agent";
    /** The document returned by a {@link #TypeIndexService} (a paginated list of types). */
    public static final Resource TypeIndex = r("TypeIndex");
    /** The synthetic, query-derived result page returned by a {@link #TypeSearchService}. */
    public static final Resource ContainerPage = r("ContainerPage");

    // ----- Properties -----
    /** Links a resource to its storage description (also used as a Link relation). */
    public static final Property storageDescription = p("storageDescription");
    /** The list of resources contained in a container. */
    public static final Property items = p("items");
    /** A capability supported by the storage. */
    public static final Property capability = p("capability");
    /** A service associated with the storage. */
    public static final Property service = p("service");
    /** The URI of a service endpoint. */
    public static final Property serviceEndpoint = p("serviceEndpoint");
    /** Supported subscription type(s) at a notification service. */
    public static final Property subscriptionType = p("subscriptionType");
    /** The URL of a subscription resource or connection endpoint. */
    public static final Property subscription = p("subscription");
    /** The Activity Streams 2.0 activity payload carried within a notification. */
    public static final Property activity = p("activity");
    /** The set of resource URIs covered by a subscription. */
    public static final Property topic = p("topic");
    /** The URI identifying the LWS storage that emitted a notification. */
    public static final Property storage = p("storage");

    // ----- Terms used by this implementation for server-managed metadata -----
    // (The LWS draft leaves the administrative/registry model unspecified; these terms
    //  live in the LWS namespace by convention and are only used internally.)
    /** Containment relation between a container and a contained resource (administrative). */
    public static final Property contains = p("contains");
    /** The parent container of a resource (administrative). */
    public static final Property parent = p("parent");
    /** The owner (WebID / controlled identifier) of a resource (administrative). */
    public static final Property owner = p("owner");
    /** Whether a resource is publicly readable (administrative). */
    public static final Property publicRead = p("publicRead");
    /** The opaque entity-tag of a resource (administrative). */
    public static final Property etag = p("etag");
    /** The storage-relative key of a non-RDF resource's binary content (administrative). */
    public static final Property binaryKey = p("binaryKey");
    /** The byte size of a non-RDF resource (administrative). */
    public static final Property byteSize = p("byteSize");
    /** The hex SHA-256 of a non-RDF resource's content (administrative; for RFC 9530 Repr-Digest). */
    public static final Property contentSha256 = p("contentSha256");
    /** The destination inbox URL of a webhook subscription. */
    public static final Property inbox = p("inbox");
    /** The expiry instant of a subscription. */
    public static final Property expires = p("expires");
    /** Whether a subscription is currently active (administrative). */
    public static final Property active = p("active");
    /** Count of consecutive failed deliveries for a subscription (administrative). */
    public static final Property failureCount = p("failureCount");
}
