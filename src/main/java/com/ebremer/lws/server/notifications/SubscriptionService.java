package com.ebremer.lws.server.notifications;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Optional;
import java.util.UUID;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.rdfconnection.RDFConnection;
import org.apache.jena.vocabulary.DCTerms;
import org.apache.jena.vocabulary.RDF;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Manages webhook subscriptions: creation (with authorization enforcement over every topic),
 * listing, retrieval, deletion and delivery bookkeeping. Subscriptions are persisted as RDF in
 * a dedicated named graph.
 *
 * @author Erich Bremer
 */
public final class SubscriptionService {

    /** Named graph holding subscription metadata. */
    public static final String SUB_GRAPH = "urn:x-lws:subscriptions";

    /** Bound on topics per subscription: every one is re-scanned on every resource event. */
    private static final int MAX_TOPICS = 64;

    private final RdfStore rdf;
    private final ResourceService resources;
    private final LwsConfiguration config;
    private final Clock clock;
    private final OutboundFetchPolicy deliveryPolicy;
    private final AtomicLong version = new AtomicLong();
    private volatile Snapshot snapshot;

    public SubscriptionService(RdfStore rdf, ResourceService resources, LwsConfiguration config, Clock clock) {
        this(rdf, resources, config, clock, OutboundFetchPolicy.forDelivery(config));
    }

    public SubscriptionService(RdfStore rdf, ResourceService resources, LwsConfiguration config, Clock clock,
            OutboundFetchPolicy deliveryPolicy) {
        this.rdf = rdf;
        this.resources = resources;
        this.config = config;
        this.clock = clock;
        this.deliveryPolicy = deliveryPolicy;
    }

    /**
     * Create a subscription from a JSON(-LD) request. The subscriber MUST be authorized to read
     * every requested topic (LWS notifications spec).
     *
     * @throws LwsException 400 for malformed requests, 403 if a topic is not readable
     */
    public Subscription create(LwsPrincipal subscriber, JsonObject request) {
        // An unauthenticated subscriber cannot be held to a quota, cannot manage what it created
        // (requireManage has no WebID to match), and can point the server's signed POSTs anywhere
        // the delivery policy allows. Off by default.
        if (LwsPrincipal.isAnonymous(subscriber) && !config.subscriptionsAllowAnonymous()) {
            throw LwsException.unauthorized("Authentication is required to create a subscription");
        }
        if (!hasType(request, "WebhookSubscription")) {
            throw LwsException.badRequest("Unsupported subscription type; expected WebhookSubscription");
        }
        List<String> topics = topics(request);
        if (topics.isEmpty()) {
            throw LwsException.badRequest("A subscription must declare at least one topic");
        }
        if (topics.size() > MAX_TOPICS) {
            throw LwsException.badRequest("A subscription may declare at most " + MAX_TOPICS + " topics");
        }
        String inbox = stringField(request, "inbox");
        if (inbox == null) {
            throw LwsException.badRequest("A WebhookSubscription must declare an inbox");
        }
        // Refuse an unreachable-by-policy inbox now, as a 400, rather than discovering it at
        // delivery time: the inbox is client-supplied and would otherwise aim the server's
        // outbound requests at whatever it can reach.
        if (!deliveryPolicy.permits(inbox)) {
            throw LwsException.badRequest("The inbox " + inbox + " is not an acceptable delivery target");
        }
        for (String topic : topics) {
            // BOTH conditions, and the second is not redundant. It is tempting to rely on canRead
            // alone -- OwnerAuthorizer answers false for any IRI with no registry entry, so under
            // owner mode it doubles as an existence test. Under Web Access Control it does not:
            // resolve() walks ancestors' acl:default, so canRead is TRUE for an absent child of a
            // container the subscriber may read. Measured: subscribing to a hidden resource
            // answered 404 while subscribing to an absent sibling answered 201 Created and stored
            // the subscription -- create-versus-refused, which is a sharper discriminator than any
            // pair of status codes, on the very IRIs whose GET is masked.
            if (!resources.canRead(subscriber, topic) || !resources.exists(topic)) {
                throw subscriber == null || subscriber.webId() == null
                        ? LwsException.unauthorized("Authentication required to subscribe to " + topic)
                        : LwsException.notFound(topic);
            }
        }
        String subscriberWebId = subscriber == null ? null : subscriber.webId();
        int held = listFor(subscriberWebId).size();
        if (held >= config.subscriptionsMaxPerSubscriber()) {
            throw new LwsException(429, "Subscription limit reached ("
                    + config.subscriptionsMaxPerSubscriber() + "); delete an existing subscription first");
        }
        Instant expires = boundedExpiry(request);

        String id = config.subscriptionsEndpointIri() + "/" + UUID.randomUUID();
        Subscription sub = new Subscription(id, subscriber == null ? null : subscriber.webId(),
                topics, inbox, expires, true, 0, clock.instant());
        rdf.writeDo(conn -> conn.load(SUB_GRAPH, toModel(sub)));
        invalidate();
        return sub;
    }

    public Optional<Subscription> get(String id) {
        return rdf.read(conn -> {
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            q.setCommandText("CONSTRUCT { ?s ?p ?o } WHERE { GRAPH ?g { ?s ?p ?o } }");
            q.setIri("g", SUB_GRAPH);
            q.setIri("s", id);
            Model m = conn.queryConstruct(q.asQuery());
            return m.isEmpty() ? Optional.empty() : Optional.of(fromModel(m, id));
        });
    }

    public List<Subscription> listFor(String subscriberWebId) {
        List<Subscription> out = new ArrayList<>();
        for (Subscription s : all()) {
            if (subscriberWebId == null ? s.subscriberWebId() == null
                    : subscriberWebId.equals(s.subscriberWebId())) {
                out.add(s);
            }
        }
        return out;
    }

    /**
     * Every subscription, served from an in-memory snapshot.
     *
     * <p>This is on the hot path: {@link NotificationEmitter} asks which subscriptions match on
     * <em>every</em> resource change, and the answer used to be a {@code conn.fetch(SUB_GRAPH)} —
     * a full materialisation and re-parse of the whole subscription graph, in its own transaction,
     * on the writer's request thread. A {@code DELETE … Depth: infinity} over a few thousand
     * resources with a few hundred subscriptions therefore ran that many transactions inside one
     * HTTP request (finding M32).
     *
     * <p>The snapshot is invalidated by every mutation through this service, and the version is read
     * <em>before</em> the load so a write that lands during a load is not lost: the next reader sees
     * the mismatch and reloads. The returned list is immutable and shared, so callers must not
     * mutate it.
     *
     * <p><em>Deviation from the suggested fix,</em> which was a topic-filtered SELECT plus a cache.
     * The SELECT is not worth writing: a container topic matches by IRI prefix, so the filter is
     * {@code STRSTARTS} over a set that is now already in memory, and scanning a few hundred records
     * in a list costs nothing next to the transaction the cache removes. Filtering in SPARQL would
     * put the prefix rule in two places — {@link Subscription#covers} and a query string — where
     * they could disagree about what a topic covers.
     */
    public List<Subscription> all() {
        long seen = version.get();
        Snapshot current = snapshot;
        if (current != null && current.version() == seen) {
            return current.subscriptions();
        }
        List<Subscription> loaded = rdf.read(conn -> {
            Model m = conn.fetch(SUB_GRAPH);
            List<Subscription> out = new ArrayList<>();
            m.listResourcesWithProperty(RDF.type, LWS.WebhookSubscription)
                    .forEachRemaining(r -> out.add(fromModel(m, r.getURI())));
            return List.copyOf(out);
        });
        snapshot = new Snapshot(seen, loaded);
        return loaded;
    }

    /** Discard the cached snapshot; called after every mutation of the subscription graph. */
    private void invalidate() {
        version.incrementAndGet();
    }

    private record Snapshot(long version, List<Subscription> subscriptions) {
    }

    /** Active, unexpired subscriptions whose topics cover the given resource. */
    public List<Subscription> activeMatching(String resourceIri) {
        Instant now = clock.instant();
        List<Subscription> out = new ArrayList<>();
        for (Subscription s : all()) {
            if (s.active() && !s.isExpired(now) && s.covers(resourceIri)) {
                out.add(s);
            }
        }
        return out;
    }

    public void delete(String id) {
        rdf.writeDo(conn -> deleteSubject(conn, id));
        invalidate();
    }

    /** Delete subscriptions whose expiry has passed. Returns the number removed. */
    public int purgeExpired(Instant now) {
        int removed = 0;
        for (Subscription s : all()) {
            if (s.isExpired(now)) {
                delete(s.id());
                removed++;
            }
        }
        return removed;
    }

    /**
     * The requested expiry, defaulted and capped by {@code lws.subscriptions.max-lifetime-seconds}.
     * A subscription that never expires is never reclaimed, and every one of them is re-read and
     * re-matched on every write in the server.
     */
    private Instant boundedExpiry(JsonObject request) {
        Instant now = clock.instant();
        Instant requested = null;
        if (request.containsKey("expires") && request.get("expires").getValueType() == JsonValue.ValueType.STRING) {
            try {
                requested = Instant.parse(request.getString("expires"));
            } catch (RuntimeException e) {
                throw LwsException.badRequest("Invalid 'expires' value; expected an RFC3339 dateTime");
            }
            if (!requested.isAfter(now)) {
                throw LwsException.badRequest("'expires' is in the past");
            }
        }
        long maxSeconds = config.subscriptionsMaxLifetimeSeconds();
        if (maxSeconds <= 0) {
            return requested; // no cap configured
        }
        Instant latest = now.plusSeconds(maxSeconds);
        if (requested == null || requested.isAfter(latest)) {
            return latest;
        }
        return requested;
    }

    /**
     * Authorize management (GET/DELETE) of a subscription: its own subscriber, or a controller of
     * the storage.
     *
     * <p>The controller test goes through the configured {@link ResourceService} rather than
     * reading {@code lws.owners} directly, so it agrees with the rest of the server — in WAC mode
     * {@code lws.owners} is consumed only to bootstrap the root ACL, and consulting it here would
     * answer differently from every resource endpoint.
     */
    /**
     * The subscriptions {@code principal} may see: its own, or all of them for a storage controller.
     *
     * <p>The decision lives here rather than in the servlet, for the reason {@code requireManage}
     * moved here too: it is the object every entry point goes through. The collection listing used
     * to be an unguarded {@code listFor(webId)}, and {@code listFor(null)} matches every
     * subscription whose {@code subscriberWebId} is null — so an unauthenticated request enumerated
     * every anonymously-created subscription, inbox URLs and topics included (finding L39).
     */
    public List<Subscription> listVisibleTo(LwsPrincipal principal) {
        if (LwsPrincipal.isAnonymous(principal)) {
            throw LwsException.unauthorized("Authentication is required to list subscriptions");
        }
        return resources.canControl(principal, config.storageRootIri())
                ? all()
                : listFor(principal.webId());
    }

    public void requireManage(LwsPrincipal principal, Subscription subscription) {
        String webId = principal == null ? null : principal.webId();
        if (webId != null && webId.equals(subscription.subscriberWebId())) {
            return;
        }
        if (resources.canControl(principal, config.storageRootIri())) {
            return;
        }
        if (webId == null) {
            throw LwsException.unauthorized("Authentication required");
        }
        throw LwsException.forbidden("Not authorized to manage this subscription");
    }

    /**
     * An RDF representation of a single subscription, for GET on a subscription resource.
     *
     * <p>Delivery bookkeeping is deliberately withheld: {@code failureCount} reports whether an
     * arbitrary client-chosen URL answered, which would turn delivery into a readable probe of the
     * server's own network. {@code active} is retained — a subscriber needs to know their
     * subscription was deactivated — but it only flips after
     * {@code lws.webhook.max-consecutive-failures}, so it carries no per-request signal.
     */
    public Model describe(Subscription subscription) {
        Model m = toModel(subscription);
        m.removeAll(m.getResource(subscription.id()), LWS.failureCount, null);
        return m;
    }

    /**
     * Deactivate a subscription outright, without waiting for the consecutive-failure count. Used
     * when the inbox answers {@code 410 Gone}, which is the subscriber saying so explicitly.
     */
    public void deactivate(String id) {
        rdf.writeDo(conn -> {
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            q.setCommandText("CONSTRUCT { ?s ?p ?o } WHERE { GRAPH ?g { ?s ?p ?o } }");
            q.setIri("g", SUB_GRAPH);
            q.setIri("s", id);
            Model m = conn.queryConstruct(q.asQuery());
            if (m.isEmpty()) {
                return;
            }
            Subscription s = fromModel(m, id);
            deleteSubject(conn, id);
            conn.load(SUB_GRAPH, toModel(new Subscription(s.id(), s.subscriberWebId(), s.topics(),
                    s.inbox(), s.expires(), false, s.failureCount(), s.created())));
        });
        invalidate();
    }

    public void recordDelivery(String id, boolean success) {
        rdf.writeDo(conn -> {
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            q.setCommandText("CONSTRUCT { ?s ?p ?o } WHERE { GRAPH ?g { ?s ?p ?o } }");
            q.setIri("g", SUB_GRAPH);
            q.setIri("s", id);
            Model m = conn.queryConstruct(q.asQuery());
            if (m.isEmpty()) {
                return;
            }
            Subscription s = fromModel(m, id);
            int failures = success ? 0 : s.failureCount() + 1;
            boolean active = s.active() && failures < config.webhookMaxConsecutiveFailures();
            Subscription updated = new Subscription(s.id(), s.subscriberWebId(), s.topics(), s.inbox(),
                    s.expires(), active, failures, s.created());
            deleteSubject(conn, id);
            conn.load(SUB_GRAPH, toModel(updated));
        });
        invalidate();
    }

    private void deleteSubject(RDFConnection conn, String id) {
        ParameterizedSparqlString u = new ParameterizedSparqlString();
        u.setCommandText("DELETE WHERE { GRAPH ?g { ?s ?p ?o } }");
        u.setIri("g", SUB_GRAPH);
        u.setIri("s", id);
        conn.update(u.asUpdate());
    }

    // ----- JSON helpers -----

    private static boolean hasType(JsonObject request, String type) {
        JsonValue t = request.get("type");
        if (t == null) {
            return false;
        }
        if (t.getValueType() == JsonValue.ValueType.STRING) {
            return ((JsonString) t).getString().endsWith(type);
        }
        if (t.getValueType() == JsonValue.ValueType.ARRAY) {
            for (JsonValue v : t.asJsonArray()) {
                if (v.getValueType() == JsonValue.ValueType.STRING && ((JsonString) v).getString().endsWith(type)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<String> topics(JsonObject request) {
        List<String> out = new ArrayList<>();
        JsonValue t = request.get("topic");
        if (t == null) {
            return out;
        }
        if (t.getValueType() == JsonValue.ValueType.STRING) {
            out.add(((JsonString) t).getString());
        } else if (t.getValueType() == JsonValue.ValueType.ARRAY) {
            JsonArray arr = t.asJsonArray();
            for (JsonValue v : arr) {
                if (v.getValueType() == JsonValue.ValueType.STRING) {
                    out.add(((JsonString) v).getString());
                }
            }
        }
        return out;
    }

    private static String stringField(JsonObject request, String name) {
        JsonValue v = request.get(name);
        return (v != null && v.getValueType() == JsonValue.ValueType.STRING) ? ((JsonString) v).getString() : null;
    }

    // ----- RDF mapping -----

    private Model toModel(Subscription s) {
        Model m = ModelFactory.createDefaultModel();
        Resource r = m.createResource(s.id());
        r.addProperty(RDF.type, LWS.WebhookSubscription);
        if (s.subscriberWebId() != null) {
            r.addProperty(LWS.owner, m.createResource(s.subscriberWebId()));
        }
        for (String topic : s.topics()) {
            r.addProperty(LWS.topic, m.createResource(topic));
        }
        r.addProperty(LWS.inbox, m.createResource(s.inbox()));
        if (s.expires() != null) {
            r.addProperty(LWS.expires, m.createTypedLiteral(s.expires().toString(), XSDDatatype.XSDdateTime));
        }
        r.addLiteral(LWS.active, s.active());
        r.addLiteral(LWS.failureCount, s.failureCount());
        if (s.created() != null) {
            r.addProperty(DCTerms.created, m.createTypedLiteral(s.created().toString(), XSDDatatype.XSDdateTime));
        }
        return m;
    }

    private Subscription fromModel(Model m, String id) {
        Resource r = m.getResource(id);
        String owner = r.hasProperty(LWS.owner) ? r.getProperty(LWS.owner).getResource().getURI() : null;
        List<String> topics = new ArrayList<>();
        for (Statement st : r.listProperties(LWS.topic).toList()) {
            RDFNode o = st.getObject();
            // isURIResource, not isResource: a blank node is a resource whose getURI() is null, and
            // a null topic would propagate into every later comparison. This graph is server-written
            // so it cannot happen today; the point is that the pattern is not left here to copy.
            if (o.isURIResource()) {
                topics.add(o.asResource().getURI());
            }
        }
        String inbox = r.hasProperty(LWS.inbox) ? r.getProperty(LWS.inbox).getResource().getURI() : null;
        Instant expires = r.hasProperty(LWS.expires) ? Instant.parse(r.getProperty(LWS.expires).getString()) : null;
        boolean active = r.hasProperty(LWS.active) && r.getProperty(LWS.active).getBoolean();
        int failureCount = r.hasProperty(LWS.failureCount) ? r.getProperty(LWS.failureCount).getInt() : 0;
        Instant created = r.hasProperty(DCTerms.created) ? Instant.parse(r.getProperty(DCTerms.created).getString()) : null;
        return new Subscription(id, owner, topics, inbox, expires, active, failureCount, created);
    }
}
