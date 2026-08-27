package com.ebremer.lws.server.core;

import java.io.ByteArrayInputStream;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.UUID;
import java.util.function.Supplier;
import jakarta.json.Json;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonString;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdfconnection.RDFConnection;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.vocab.LDP;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Stores and evaluates LWS <em>access requests</em> and <em>access grants</em>, per
 * <a href="https://w3c.github.io/lws-protocol/lws10-core/#access-requests">lws10-core access
 * requests</a>. Each is an {@code application/lws+json} document persisted (with the server-assigned
 * {@code id}) in a dedicated graph; the endpoints behave as LWS containers.
 *
 * <p>Grants are <em>enforced</em> by {@code GrantAuthorizer}, which calls
 * {@link #grants(LwsPrincipal, String, AclMode, Instant)}: an active grant whose {@code action}
 * covers the requested mode, whose {@code assignee} is the principal (or the public
 * {@code foaf:Agent}), and whose {@code target} covers the resource, authorizes the operation —
 * regardless of the underlying authorization model — so revoking a grant (deleting the record)
 * immediately removes the access. Constraints are evaluated fail-closed: {@code dateTime} and
 * {@code client} are honoured; a grant carrying any other constraint ({@code purpose}/{@code
 * mediaType}/{@code type}) is treated as inactive rather than over-granting.
 *
 * @author Erich Bremer
 */
public final class AccessService {

    private static final org.slf4j.Logger log =
            org.slf4j.LoggerFactory.getLogger(AccessService.class);

    /** The two kinds of access document. */
    public enum Kind { REQUEST, GRANT }

    /** A stored record: its id, kind, creator WebID, and the canonical JSON document. */
    public record Record(String id, Kind kind, String creator, String json) {
    }

    static final String GRAPH = "urn:x-lws:access";
    private static final String CREATOR = "urn:x-lws:accessCreator";
    private static final String JSON = "urn:x-lws:accessJson";
    /**
     * One triple per assignee named by a grant's policies, purely so a check can ask the store for
     * the grants that could apply to one agent instead of for all of them (prior-review finding 12).
     * A denormalisation of the stored JSON, and never the authority: see {@link #storedGrants}.
     */
    private static final String ASSIGNEE = "urn:x-lws:accessAssignee";

    private final RdfStore rdf;
    private final LwsConfiguration config;
    private final ResourceRegistry registry;

    /** Fast path: skip grant evaluation entirely when no grants exist. */
    /**
     * Whether any access grant is stored — a fast path that skips grant evaluation entirely.
     *
     * <p>Rechecked at most once every {@link #GRANTS_RECHECK_NANOS}, because being wrong in the
     * {@code false} direction silently disables <em>all</em> grant-based authorization and nothing
     * surfaces it. The flag is only maintained by writes through this instance, so a second server
     * sharing the store, a restore, or any out-of-band write left it stale until the process
     * restarted. Being wrong in the {@code true} direction merely costs an evaluation that finds
     * nothing, which is why the recheck only ever needs to run while it is false.
     */
    private volatile boolean hasGrants;
    private volatile long grantsCheckedAt;

    /** How long a negative {@code hasGrants} answer may be trusted before it is re-counted. */
    private static final long GRANTS_RECHECK_NANOS = java.util.concurrent.TimeUnit.SECONDS.toNanos(30);

    /**
     * Whether an {@code inbox} on a submitted document is an acceptable delivery target. Supplied
     * as a predicate rather than an {@code OutboundFetchPolicy} so {@code core} keeps no dependency
     * on {@code auth}; the server wires in the notification delivery policy.
     */
    private final Predicate<String> inboxPolicy;

    /**
     * Whether the WebID that issued a grant is <em>still</em> a storage controller.
     *
     * <p>Supplied as a predicate for the same reason as {@link #inboxPolicy} — {@code core} keeps no
     * dependency on {@code auth} — and, more importantly, so the server is forced to choose
     * <em>which</em> authorizer answers. It must be the <b>base</b> one: this class is what the
     * grant authorizer calls, so routing the question back through that authorizer would put grant
     * evaluation inside grant evaluation.
     */
    private final Predicate<String> controllerPolicy;

    public AccessService(RdfStore rdf, LwsConfiguration config, ResourceRegistry registry,
            Predicate<String> inboxPolicy, Predicate<String> controllerPolicy) {
        this.rdf = rdf;
        this.config = config;
        this.registry = registry;
        this.inboxPolicy = inboxPolicy;
        this.controllerPolicy = controllerPolicy;
        this.hasGrants = countGrants() > 0;
        if (hasGrants) {
            indexLegacyGrants();
        }
    }

    /** How many grants are stored, and how many of those no longer authorize anything. */
    public record Census(int total, int inert) {
    }

    /**
     * Count the stored grants, and how many were issued by an agent who is no longer a storage
     * controller. Reported at startup: a grant is invisible in {@code lws.owners} and in every ACL,
     * so an operator who inherits a storage has no other way to notice one.
     */
    /** {@link #hasGrants}, re-counted if the last negative answer is old enough to distrust. */
    private boolean grantsExist() {
        if (hasGrants) {
            return true;
        }
        long now = System.nanoTime();
        if (now - grantsCheckedAt < GRANTS_RECHECK_NANOS) {
            return false;
        }
        grantsCheckedAt = now;
        hasGrants = countGrants() > 0;
        return hasGrants;
    }

    public Census census() {
        List<Stored> stored = storedGrants();
        Map<String, Boolean> controllers = new HashMap<>();
        int inert = 0;
        for (Stored grant : stored) {
            if (!controllers.computeIfAbsent(grant.creator(), controllerPolicy::test)) {
                inert++;
            }
        }
        return new Census(stored.size(), inert);
    }

    /**
     * The distinct WebIDs that issued the stored grants.
     *
     * <p>Projected in SPARQL rather than derived from {@link #storedGrants()}, and short-circuited
     * when no grant exists. This runs on the <em>warm-up</em> path — {@code GrantAuthorizer.prepare},
     * which every read, write and delete calls, once per descendant on a recursive delete — and
     * building it from the full records meant transferring the complete JSON document of every grant
     * in the storage, on every request, to keep only the issuer column and throw the rest away. That
     * is the cost prior-review finding 12 is about, on the one path the assignee index does not
     * narrow, because it is not asking about an assignee.
     */
    public Set<String> grantIssuers() {
        if (!grantsExist()) {
            return Set.of();
        }
        return rdf.read(conn -> {
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            q.setCommandText("SELECT DISTINCT ?creator WHERE { GRAPH ?g { ?s a ?t . ?s ?creatorP ?creator } }");
            q.setIri("g", GRAPH);
            q.setIri("t", LWS.AccessGrant.getURI());
            q.setIri("creatorP", CREATOR);
            Set<String> issuers = new LinkedHashSet<>();
            conn.querySelect(q.asQuery(), row -> {
                if (row.getResource("creator") != null && row.getResource("creator").isURIResource()) {
                    issuers.add(row.getResource("creator").getURI());
                }
            });
            return issuers;
        });
    }

    /** The media type and types of a grant target, loaded lazily for constraint evaluation. */
    private record TargetMetadata(String mediaType, Set<String> types) {
    }

    private Resource type(Kind kind) {
        return kind == Kind.REQUEST ? LWS.AccessRequest : LWS.AccessGrant;
    }

    private String endpoint(Kind kind) {
        return kind == Kind.REQUEST ? config.accessRequestsEndpointIri() : config.accessGrantsEndpointIri();
    }

    // ----- lifecycle -----

    /** Validate, assign an id, persist, and return the record. */
    public Record create(LwsPrincipal creator, Kind kind, byte[] body) {
        JsonObject doc = parseObject(body);
        String id = endpoint(kind) + "/" + UUID.randomUUID();
        JsonObject normalized = normalize(doc, kind, id);
        String creatorWebId = creator == null ? null : creator.webId();
        rdf.writeDo(conn -> {
            ParameterizedSparqlString u = new ParameterizedSparqlString();
            u.setCommandText("INSERT DATA { GRAPH ?g { ?s a ?t . ?s ?creatorP ?creator . ?s ?jsonP ?json } }");
            u.setIri("g", GRAPH);
            u.setIri("s", id);
            u.setIri("t", type(kind).getURI());
            u.setIri("creatorP", CREATOR);
            u.setIri("creator", creatorWebId == null ? LWS.FOAF_AGENT : creatorWebId);
            u.setIri("jsonP", JSON);
            u.setLiteral("json", normalized.toString());
            conn.update(u.asUpdate());
            if (kind == Kind.GRANT) {
                indexAssignees(conn, id, normalized);
            }
        });
        if (kind == Kind.GRANT) {
            hasGrants = true;
        }
        return new Record(id, kind, creatorWebId, normalized.toString());
    }

    public List<Record> all(Kind kind) {
        return rdf.read(conn -> {
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            q.setCommandText("SELECT ?s ?creator ?json WHERE { GRAPH ?g { ?s a ?t . ?s ?creatorP ?creator . "
                    + "?s ?jsonP ?json } } ORDER BY ?s");
            q.setIri("g", GRAPH);
            q.setIri("t", type(kind).getURI());
            q.setIri("creatorP", CREATOR);
            q.setIri("jsonP", JSON);
            List<Record> out = new ArrayList<>();
            conn.querySelect(q.asQuery(), row -> out.add(new Record(row.getResource("s").getURI(), kind,
                    row.getResource("creator").getURI(), row.getLiteral("json").getString())));
            return out;
        });
    }

    public Optional<Record> get(String id) {
        return rdf.read(conn -> {
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            q.setCommandText("SELECT ?t ?creator ?json WHERE { GRAPH ?g { ?s a ?t . ?s ?creatorP ?creator . "
                    + "?s ?jsonP ?json } }");
            q.setIri("g", GRAPH);
            q.setIri("s", id);
            q.setIri("creatorP", CREATOR);
            q.setIri("jsonP", JSON);
            Record[] holder = new Record[1];
            conn.querySelect(q.asQuery(), row -> {
                Kind kind = row.getResource("t").getURI().equals(LWS.AccessGrant.getURI()) ? Kind.GRANT : Kind.REQUEST;
                holder[0] = new Record(id, kind, row.getResource("creator").getURI(),
                        row.getLiteral("json").getString());
            });
            return Optional.ofNullable(holder[0]);
        });
    }

    public void delete(String id) {
        rdf.writeDo(conn -> {
            ParameterizedSparqlString u = new ParameterizedSparqlString();
            u.setCommandText("DELETE WHERE { GRAPH ?g { ?s ?p ?o } }");
            u.setIri("g", GRAPH);
            u.setIri("s", id);
            conn.update(u.asUpdate());
        });
        hasGrants = countGrants() > 0;
    }

    /**
     * The inboxes to notify when {@code record} is created (lws10-core access requests): the
     * document's own {@code inbox}; for a request, the configured storage-controller inbox; and for a
     * grant, the inbox of the associated request it references via a {@code request} link.
     */
    public Set<String> notificationInboxes(Record record) {
        Set<String> inboxes = new LinkedHashSet<>();
        JsonObject doc = tryParse(record.json());
        if (doc == null) {
            return inboxes;
        }
        addIfPresent(inboxes, string(doc, "inbox"));
        if (record.kind() == Kind.REQUEST) {
            addIfPresent(inboxes, config.accessControllerInbox());
        } else {
            String requestRef = string(doc, "request");
            if (requestRef != null) {
                get(requestRef).filter(r -> r.kind() == Kind.REQUEST).ifPresent(request -> {
                    JsonObject requestDoc = tryParse(request.json());
                    addIfPresent(inboxes, requestDoc == null ? null : string(requestDoc, "inbox"));
                });
            }
        }
        return inboxes;
    }

    private static void addIfPresent(Set<String> inboxes, String inbox) {
        if (inbox != null && !inbox.isBlank()) {
            inboxes.add(inbox);
        }
    }

    // ----- grant evaluation (used by GrantAuthorizer) -----

    /** A stored grant: the WebID that issued it, and the document itself. */
    private record Stored(String creator, String json) {
    }

    /** True if an active grant authorizes {@code principal} to perform {@code mode} on {@code iri}. */
    public boolean grants(LwsPrincipal principal, String iri, AclMode mode, Instant now) {
        if (mode == AclMode.CONTROL || !grantsExist()) {
            return false; // grants never confer Control, and skip when there are none
        }
        List<Stored> documents = storedGrants(principal);
        // Resource metadata (media type, types) is loaded once, on demand, only if a constraint needs it.
        TargetMetadata[] cache = new TargetMetadata[1];
        Supplier<TargetMetadata> target = () -> {
            if (cache[0] == null) {
                cache[0] = loadTargetMetadata(iri);
            }
            return cache[0];
        };
        // One controller resolution per distinct issuer, not per grant. Only controllers can issue,
        // so issuers repeat and are usually a single WebID; measured on a 200-grant fixture, asking
        // per grant costs +29% under WAC and +190% in owner mode, while asking per issuer costs
        // under 1%. The memo is therefore the design, not a tidy-up. It is deliberately local to one
        // call: promoting it to the request would freeze an authorization answer for a whole request.
        Map<String, Boolean> controllers = new HashMap<>();
        for (Stored stored : documents) {
            // A grant carries only the authority of the agent who issued it, so that authority is
            // asked about again here rather than trusted from issuance time. An issuer dropped from
            // lws.owners, or stripped of acl:Control by an ACL edit, stops authorizing on the very
            // next request — no restart, and no stored record to clean up.
            if (!controllers.computeIfAbsent(stored.creator(), controllerPolicy::test)) {
                continue;
            }
            JsonObject doc = parsed(stored.json());
            if (doc == null || !doc.containsKey("access")
                    || doc.get("access").getValueType() != JsonValue.ValueType.ARRAY) {
                continue;
            }
            for (JsonValue policyValue : doc.getJsonArray("access")) {
                if (policyValue.getValueType() == JsonValue.ValueType.OBJECT
                        && policyAuthorizes(policyValue.asJsonObject(), principal, iri, mode, now, target)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Every stored grant with its issuer.
     *
     * <p>The join on {@code ?creator} is INNER on purpose: a grant with no recorded issuer drops out
     * of the result set and authorizes nothing, rather than being evaluated with nobody's authority
     * behind it. One {@code OPTIONAL} here would make that fail open.
     */
    private List<Stored> storedGrants() {
        return storedGrants(null);
    }

    /**
     * The stored grants that could possibly apply to {@code principal}, or all of them when
     * {@code principal} is {@code null}.
     *
     * <p>The narrowing is an index, not a decision (prior-review finding 12). Every check used to
     * pull every grant document in the storage across the wire and parse each one, so a storage
     * holding grants for ten thousand different agents did ten thousand JSON parses to answer a
     * question about one of them. Each grant now also stores its policies' assignees as their own
     * triples, and the query filters on them.
     *
     * <p><b>The JSON stays authoritative.</b> The filter can only ever remove candidates from
     * consideration; {@code assigneeMatches} still reads the assignee out of the document itself. So
     * an index that disagreed with the document it indexes cannot grant access — the worst it can do
     * is fail to consider a grant, which denies.
     *
     * <p>And a grant written before this existed has no index triples at all, which the
     * {@code !BOUND} arm below admits unconditionally: a legacy grant is evaluated exactly as it
     * always was rather than silently ceasing to apply. That is what makes this safe to deploy
     * without a migration; {@link #indexLegacyGrants()} runs one anyway, so the benefit is not
     * confined to grants written from here on.
     */
    private List<Stored> storedGrants(LwsPrincipal principal) {
        return rdf.read(conn -> {
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            if (principal == null || principal.webId() == null) {
                q.setCommandText("SELECT ?creator ?json WHERE { GRAPH ?g { ?s a ?t . "
                        + "?s ?creatorP ?creator . ?s ?jsonP ?json } }");
            } else {
                q.setCommandText("SELECT DISTINCT ?creator ?json WHERE { GRAPH ?g { "
                        + "?s a ?t . ?s ?creatorP ?creator . ?s ?jsonP ?json . "
                        + "OPTIONAL { ?s ?assigneeP ?assignee } } "
                        + "FILTER( !BOUND(?assignee) || ?assignee = ?me || ?assignee = ?anyone ) }");
                q.setIri("assigneeP", ASSIGNEE);
                q.setIri("me", principal.webId());
                q.setIri("anyone", LWS.FOAF_AGENT);
            }
            q.setIri("g", GRAPH);
            q.setIri("t", LWS.AccessGrant.getURI());
            q.setIri("creatorP", CREATOR);
            q.setIri("jsonP", JSON);
            List<Stored> out = new ArrayList<>();
            conn.querySelect(q.asQuery(), row -> {
                if (row.getResource("creator") != null && row.getResource("creator").isURIResource()) {
                    out.add(new Stored(row.getResource("creator").getURI(),
                            row.getLiteral("json").getString()));
                }
            });
            return out;
        });
    }

    /**
     * Parsed grant documents, keyed by the document text itself.
     *
     * <p>Keyed by content, so there is no invalidation to get wrong: a changed grant is a different
     * string and simply misses. Bounded by total characters rather than entry count, because the
     * values are documents and a count says nothing about the heap. Every check used to re-parse
     * every candidate grant's JSON; for a storage with a few hundred grants that was the largest
     * single cost in an authorization decision (prior-review finding 12).
     */
    private static final long DOCUMENT_CACHE_CHARS = 4L * 1024 * 1024;

    private final com.github.benmanes.caffeine.cache.Cache<String, JsonObject> parsedGrants =
            com.github.benmanes.caffeine.cache.Caffeine.newBuilder()
                    .maximumWeight(DOCUMENT_CACHE_CHARS)
                    .<String, JsonObject>weigher((json, doc) -> json.length())
                    .build();

    /** {@link #tryParse} through the content-keyed cache; {@code null} for a document that will not parse. */
    private JsonObject parsed(String json) {
        JsonObject cached = parsedGrants.getIfPresent(json);
        if (cached != null) {
            return cached;
        }
        JsonObject doc = tryParse(json);
        if (doc != null) {
            parsedGrants.put(json, doc);
        }
        return doc;
    }

    private boolean policyAuthorizes(JsonObject policy, LwsPrincipal principal, String iri, AclMode mode,
            Instant now, Supplier<TargetMetadata> target) {
        return typeIncludes(policy, "AccessPolicy")
                && assigneeMatches(policy, principal)
                && actionGrants(policy, mode)
                && targetCovers(policy, iri)
                && constraintsSatisfied(policy, principal, now, target);
    }

    private static boolean assigneeMatches(JsonObject policy, LwsPrincipal principal) {
        String assignee = string(policy, "assignee");
        if (assignee == null) {
            return false;
        }
        if (assignee.equals(LWS.FOAF_AGENT)) {
            return true; // public
        }
        return principal != null && assignee.equals(principal.webId());
    }

    /**
     * Whether a policy's ODRL {@code action} list covers the mode being asked about.
     *
     * <p>{@code modify} and {@code delete} used to be a single arm — {@code case WRITE ->
     * actions.contains("modify") || actions.contains("delete")} — because the server had only one
     * destructive mode to map them onto. Each therefore implied the other, and the direction that
     * matters is that a grant saying only {@code "action":["modify"]}, issued so somebody could edit
     * one document, authorized {@code DELETE} of it and, on a container, {@code DELETE} with
     * {@code Depth: infinity} of everything beneath it (finding M8).
     *
     * <p>The two are separate modes now, and this is the one place in the server where the
     * distinction is visible: Web Access Control has no delete permission, and owner-based
     * authorization has no per-action model at all.
     */
    private static boolean actionGrants(JsonObject policy, AclMode mode) {
        List<String> actions = strings(policy, "action");
        return switch (mode) {
            case READ -> actions.contains("read");
            case APPEND -> actions.contains("create");
            case WRITE -> actions.contains("modify");
            case DELETE -> actions.contains("delete");
            case CONTROL -> false;
        };
    }

    private static boolean targetCovers(JsonObject policy, String iri) {
        JsonValue target = policy.get("target");
        if (target == null || target.getValueType() != JsonValue.ValueType.OBJECT) {
            return false; // fail-closed: a grant must name its targets to enforce
        }
        for (String value : strings(target.asJsonObject(), "value")) {
            if (iri.equals(value) || (value.endsWith("/") && iri.startsWith(value))) {
                return true;
            }
        }
        return false;
    }

    private boolean constraintsSatisfied(JsonObject policy, LwsPrincipal principal, Instant now,
            Supplier<TargetMetadata> target) {
        JsonValue constraints = policy.get("constraint");
        if (constraints == null) {
            return true;
        }
        if (constraints.getValueType() != JsonValue.ValueType.ARRAY) {
            return false;
        }
        for (JsonValue c : constraints.asJsonArray()) {
            if (c.getValueType() != JsonValue.ValueType.OBJECT
                    || !constraintSatisfied(c.asJsonObject(), principal, now, target)) {
                return false;
            }
        }
        return true;
    }

    private boolean constraintSatisfied(JsonObject constraint, LwsPrincipal principal, Instant now,
            Supplier<TargetMetadata> target) {
        String left = string(constraint, "leftOperand");
        String operator = string(constraint, "operator");
        if (left == null || operator == null) {
            return false;
        }
        switch (left) {
            case "dateTime" -> {
                Instant bound = parseInstant(string(constraint, "rightOperand"));
                if (bound == null) {
                    return false;
                }
                return switch (operator) {
                    case "gteq" -> !now.isBefore(bound);
                    case "lteq" -> !now.isAfter(bound);
                    default -> false;
                };
            }
            case "client" -> {
                String client = principal == null ? null : principal.clientId();
                if (client == null) {
                    return false;
                }
                return switch (operator) {
                    case "eq" -> client.equals(string(constraint, "rightOperand"));
                    case "isAnyOf" -> strings(constraint, "rightOperand").contains(client);
                    default -> false;
                };
            }
            case "mediaType" -> {
                String mediaType = target.get().mediaType();
                if (mediaType == null) {
                    return false;
                }
                return switch (operator) {
                    case "eq" -> mediaType.equals(string(constraint, "rightOperand"));
                    case "isAnyOf" -> strings(constraint, "rightOperand").contains(mediaType);
                    default -> false;
                };
            }
            case "type" -> {
                Set<String> types = target.get().types();
                return switch (operator) {
                    case "eq" -> types.contains(string(constraint, "rightOperand"));
                    case "isAnyOf" -> strings(constraint, "rightOperand").stream().anyMatch(types::contains);
                    default -> false;
                };
            }
            case "purpose" -> {
                // The client declares its purpose(s) per request (LWS-Purpose header); a grant's
                // purpose constraint applies only when a declared purpose matches (fail-closed).
                Set<String> declared = RequestContext.purposes();
                if (declared.isEmpty()) {
                    return false;
                }
                return switch (operator) {
                    case "eq" -> declared.contains(string(constraint, "rightOperand"));
                    case "isAnyOf" -> strings(constraint, "rightOperand").stream().anyMatch(declared::contains);
                    default -> false;
                };
            }
            // Any unknown operand cannot be evaluated -> fail-closed.
            default -> {
                return false;
            }
        }
    }

    /** Load a target's media type and types (advertised link-header types plus content rdf:types). */
    private TargetMetadata loadTargetMetadata(String iri) {
        return rdf.read(conn -> {
            LwsResource resource = registry.find(conn, iri).orElse(null);
            if (resource == null) {
                return new TargetMetadata(null, Set.of());
            }
            Set<String> types = advertisedTypes(resource.type());
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            q.setCommandText("""
                    SELECT DISTINCT ?t WHERE {
                      GRAPH ?g { ?s a ?t }
                      FILTER( sameTerm(?s, ?g) || STRSTARTS(STR(?s), CONCAT(STR(?g), "#")) )
                    }""");
            q.setIri("g", iri);
            conn.querySelect(q.asQuery(), row -> {
                if (row.get("t") != null && row.get("t").isURIResource()) {
                    types.add(row.getResource("t").getURI());
                }
            });
            return new TargetMetadata(resource.contentType(), types);
        });
    }

    /** The {@code rel="type"} IRIs the server advertises for a resource of the given kind. */
    private static Set<String> advertisedTypes(ResourceType type) {
        Set<String> types = new HashSet<>();
        types.add(LDP.RESOURCE);
        switch (type) {
            case CONTAINER -> {
                types.add(LDP.BASIC_CONTAINER);
                types.add(LWS.Container.getURI());
            }
            case RDF_SOURCE -> {
                types.add(LDP.RDF_SOURCE);
                types.add(LWS.DataResource.getURI());
            }
            case NON_RDF_SOURCE -> {
                types.add(LDP.NON_RDF_SOURCE);
                types.add(LWS.DataResource.getURI());
            }
        }
        return types;
    }

    /** Record each assignee a grant's policies name, as the index {@link #storedGrants} filters on. */
    private static void indexAssignees(RDFConnection conn, String id, JsonObject grant) {
        for (String assignee : assigneesOf(grant)) {
            ParameterizedSparqlString u = new ParameterizedSparqlString();
            u.setCommandText("INSERT DATA { GRAPH ?g { ?s ?p ?a } }");
            u.setIri("g", GRAPH);
            u.setIri("s", id);
            u.setIri("p", ASSIGNEE);
            u.setIri("a", assignee);
            conn.update(u.asUpdate());
        }
    }

    /** The assignees named by a grant's policies, as absolute URIs. */
    private static Set<String> assigneesOf(JsonObject grant) {
        Set<String> out = new LinkedHashSet<>();
        JsonValue access = grant.get("access");
        if (access == null || access.getValueType() != JsonValue.ValueType.ARRAY) {
            return out;
        }
        for (JsonValue policyValue : access.asJsonArray()) {
            if (policyValue.getValueType() != JsonValue.ValueType.OBJECT) {
                continue;
            }
            String assignee = string(policyValue.asJsonObject(), "assignee");
            if (assignee != null && isAbsoluteUri(assignee)) {
                out.add(assignee);
            }
        }
        return out;
    }

    /**
     * Add the assignee index to grants written before it existed.
     *
     * <p>Correctness does not depend on this — {@link #storedGrants} admits an unindexed grant
     * unconditionally — so a failure here is logged and the storage keeps working, just without the
     * narrowing for those grants. Run once at construction, over however many grants exist, which is
     * bounded by what a controller has issued.
     */
    private void indexLegacyGrants() {
        try {
            List<String[]> missing = rdf.read(conn -> {
                ParameterizedSparqlString q = new ParameterizedSparqlString();
                q.setCommandText("SELECT ?s ?json WHERE { GRAPH ?g { ?s a ?t . ?s ?jsonP ?json } "
                        + "FILTER NOT EXISTS { GRAPH ?g { ?s ?assigneeP ?a } } }");
                q.setIri("g", GRAPH);
                q.setIri("t", LWS.AccessGrant.getURI());
                q.setIri("jsonP", JSON);
                q.setIri("assigneeP", ASSIGNEE);
                List<String[]> out = new ArrayList<>();
                conn.querySelect(q.asQuery(), row ->
                        out.add(new String[] {row.getResource("s").getURI(),
                                row.getLiteral("json").getString()}));
                return out;
            });
            if (missing.isEmpty()) {
                return;
            }
            rdf.writeDo(conn -> {
                for (String[] grant : missing) {
                    JsonObject doc = tryParse(grant[1]);
                    if (doc != null) {
                        indexAssignees(conn, grant[0], doc);
                    }
                }
            });
        } catch (RuntimeException e) {
            // Not fatal: an unindexed grant is still evaluated, it is just not narrowed for.
            log.warn("Could not build the access-grant assignee index ({}); grant evaluation will "
                    + "consider every stored grant.", e.toString());
        }
    }

    private long countGrants() {
        return rdf.read(conn -> {
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            q.setCommandText("ASK { GRAPH ?g { ?s a ?t } }");
            q.setIri("g", GRAPH);
            q.setIri("t", LWS.AccessGrant.getURI());
            return conn.queryAsk(q.asQuery()) ? 1L : 0L;
        });
    }

    // ----- validation / parsing -----

    private JsonObject normalize(JsonObject doc, Kind kind, String id) {
        String term = kind == Kind.REQUEST ? "AccessRequest" : "AccessGrant";
        if (doc.containsKey("type") && !typeIncludes(doc, term)) {
            throw LwsException.badRequest("type must include \"" + term + "\"");
        }
        String storage = string(doc, "storage");
        if (storage == null || !isAbsoluteUri(storage)) {
            throw LwsException.badRequest("\"storage\" is required and must be an absolute URI");
        }
        // `storage` identifies the storage this document is about, so it is compared for equality
        // and NOT tested for containment: <root>sub/ is inside this storage but is not it. The
        // trailing slash is supplied because an LWS storage IRI always carries one and a client that
        // omits it plainly means the same storage. Until this check existed, a document could name
        // somebody else's storage and still be fully effective here.
        String declared = storage.endsWith("/") ? storage : storage + "/";
        if (!declared.equals(config.storageRootIri())) {
            throw LwsException.badRequest("\"storage\" must be " + config.storageRootIri());
        }
        // The document's inbox becomes a signed POST from this server the moment the record is
        // created, so an unacceptable target is refused here rather than at delivery time.
        String inbox = string(doc, "inbox");
        if (inbox != null && !inbox.isBlank() && !inboxPolicy.test(inbox)) {
            throw LwsException.badRequest("The inbox " + inbox + " is not an acceptable delivery target");
        }
        if (!doc.containsKey("access") || doc.get("access").getValueType() != JsonValue.ValueType.ARRAY
                || doc.getJsonArray("access").isEmpty()) {
            throw LwsException.badRequest("\"access\" is required and must be a non-empty array");
        }
        for (JsonValue policyValue : doc.getJsonArray("access")) {
            if (policyValue.getValueType() != JsonValue.ValueType.OBJECT) {
                throw LwsException.badRequest("each \"access\" entry must be an object");
            }
            validatePolicy(policyValue.asJsonObject());
        }
        JsonObjectBuilder builder = Json.createObjectBuilder(doc);
        if (!doc.containsKey("@context")) {
            builder.add("@context", LWS.JSON_CONTEXT);
        }
        builder.add("type", Json.createArrayBuilder().add(term));
        builder.add("id", id);
        return builder.build();
    }

    private void validatePolicy(JsonObject policy) {
        if (!typeIncludes(policy, "AccessPolicy")) {
            throw LwsException.badRequest("each access policy type must include \"AccessPolicy\"");
        }
        List<String> actions = strings(policy, "action");
        if (actions.isEmpty()) {
            throw LwsException.badRequest("each access policy requires a non-empty \"action\" array");
        }
        for (String action : actions) {
            if (!List.of("read", "modify", "create", "delete").contains(action)) {
                throw LwsException.badRequest("unsupported action: " + action);
            }
        }
        String assignee = string(policy, "assignee");
        if (assignee == null || !isAbsoluteUri(assignee)) {
            throw LwsException.badRequest("each access policy requires an \"assignee\" URI");
        }
        // Required and bounded. `targetCovers` prefix-matches these values at evaluation time, so a
        // policy with no target authorized nothing (harmless) while a target naming another storage
        // authorized everything under a prefix this server does not own. Each value is judged
        // exactly as it will be stored, with no decoding and no normalization, because that is the
        // string the prefix match will see — and because resource IRIs are built from the request
        // target as received, so a normalized check would be answering about an IRI the registry
        // never holds.
        JsonValue target = policy.get("target");
        if (target == null || target.getValueType() != JsonValue.ValueType.OBJECT) {
            throw LwsException.badRequest("each access policy requires a \"target\" object");
        }
        List<String> values = strings(target.asJsonObject(), "value");
        if (values.isEmpty()) {
            throw LwsException.badRequest("each access policy \"target\" requires a non-empty \"value\"");
        }
        for (String value : values) {
            if (Iris.toPath(config.baseUri(), value) == null) {
                throw LwsException.badRequest(
                        "target " + value + " is outside this storage (" + config.storageRootIri() + ")");
            }
        }
    }

    private static boolean typeIncludes(JsonObject obj, String term) {
        JsonValue type = obj.get("type");
        if (type == null) {
            return false;
        }
        if (type.getValueType() == JsonValue.ValueType.STRING) {
            return term.equals(((JsonString) type).getString());
        }
        if (type.getValueType() == JsonValue.ValueType.ARRAY) {
            return type.asJsonArray().stream()
                    .filter(v -> v.getValueType() == JsonValue.ValueType.STRING)
                    .anyMatch(v -> term.equals(((JsonString) v).getString()));
        }
        return false;
    }

    private static String string(JsonObject obj, String key) {
        JsonValue v = obj.get(key);
        return (v != null && v.getValueType() == JsonValue.ValueType.STRING) ? ((JsonString) v).getString() : null;
    }

    /** A value that is a string, or an array of strings, as a list. */
    private static List<String> strings(JsonObject obj, String key) {
        JsonValue v = obj.get(key);
        if (v == null) {
            return List.of();
        }
        if (v.getValueType() == JsonValue.ValueType.STRING) {
            return List.of(((JsonString) v).getString());
        }
        if (v.getValueType() == JsonValue.ValueType.ARRAY) {
            List<String> out = new ArrayList<>();
            for (JsonValue e : v.asJsonArray()) {
                if (e.getValueType() == JsonValue.ValueType.STRING) {
                    out.add(((JsonString) e).getString());
                }
            }
            return out;
        }
        return List.of();
    }

    private static Instant parseInstant(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static boolean isAbsoluteUri(String value) {
        return SearchIndexService.isAbsoluteUri(value);
    }

    private static JsonObject parseObject(byte[] body) {
        JsonLimits.requireBoundedNesting(body);
        try (var reader = Json.createReader(new ByteArrayInputStream(body))) {
            JsonStructure parsed = reader.read();
            if (parsed.getValueType() != JsonValue.ValueType.OBJECT) {
                throw LwsException.badRequest("Request body must be a JSON object");
            }
            return parsed.asJsonObject();
        } catch (JsonException | IllegalStateException | StackOverflowError e) {
            throw LwsException.badRequest("Invalid JSON: " + e);
        }
    }

    private static JsonObject tryParse(String json) {
        try (var reader = Json.createReader(new java.io.StringReader(json))) {
            JsonStructure parsed = reader.read();
            return parsed.getValueType() == JsonValue.ValueType.OBJECT ? parsed.asJsonObject() : null;
        } catch (RuntimeException | StackOverflowError e) {
            // Widened for the reason recorded on LinksetService.readUserMetadata: the provider
            // reports its own nesting cap as a bare RuntimeException and a deep document as an
            // Error, and neither was caught. Stored access records are bounded at create and are
            // never merged into, so this is defensive — it matters only for a record written by a
            // build that predates that bound.
            return null;
        }
    }
}
