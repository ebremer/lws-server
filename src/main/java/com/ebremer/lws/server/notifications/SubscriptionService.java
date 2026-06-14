package com.ebremer.lws.server.notifications;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
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

    private final RdfStore rdf;
    private final ResourceService resources;
    private final LwsConfiguration config;
    private final Clock clock;

    public SubscriptionService(RdfStore rdf, ResourceService resources, LwsConfiguration config, Clock clock) {
        this.rdf = rdf;
        this.resources = resources;
        this.config = config;
        this.clock = clock;
    }

    /**
     * Create a subscription from a JSON(-LD) request. The subscriber MUST be authorized to read
     * every requested topic (LWS notifications spec).
     *
     * @throws LwsException 400 for malformed requests, 403 if a topic is not readable
     */
    public Subscription create(LwsPrincipal subscriber, JsonObject request) {
        if (!hasType(request, "WebhookSubscription")) {
            throw LwsException.badRequest("Unsupported subscription type; expected WebhookSubscription");
        }
        List<String> topics = topics(request);
        if (topics.isEmpty()) {
            throw LwsException.badRequest("A subscription must declare at least one topic");
        }
        String inbox = stringField(request, "inbox");
        if (inbox == null) {
            throw LwsException.badRequest("A WebhookSubscription must declare an inbox");
        }
        for (String topic : topics) {
            if (!resources.canRead(subscriber, topic)) {
                throw LwsException.forbidden("Not authorized to subscribe to " + topic);
            }
        }
        Instant expires = null;
        if (request.containsKey("expires") && request.get("expires").getValueType() == JsonValue.ValueType.STRING) {
            try {
                expires = Instant.parse(request.getString("expires"));
            } catch (RuntimeException e) {
                throw LwsException.badRequest("Invalid 'expires' value; expected an RFC3339 dateTime");
            }
        }

        String id = config.subscriptionsEndpointIri() + "/" + UUID.randomUUID();
        Subscription sub = new Subscription(id, subscriber == null ? null : subscriber.webId(),
                topics, inbox, expires, true, 0, clock.instant());
        rdf.writeDo(conn -> conn.load(SUB_GRAPH, toModel(sub)));
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

    public List<Subscription> all() {
        return rdf.read(conn -> {
            Model m = conn.fetch(SUB_GRAPH);
            List<Subscription> out = new ArrayList<>();
            m.listResourcesWithProperty(RDF.type, LWS.WebhookSubscription)
                    .forEachRemaining(r -> out.add(fromModel(m, r.getURI())));
            return out;
        });
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

    /** An RDF representation of a single subscription, for GET on a subscription resource. */
    public Model describe(Subscription subscription) {
        return toModel(subscription);
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
            if (o.isResource()) {
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
