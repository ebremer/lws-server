package com.ebremer.lws.server.core;

import java.io.ByteArrayInputStream;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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

    /** The two kinds of access document. */
    public enum Kind { REQUEST, GRANT }

    /** A stored record: its id, kind, creator WebID, and the canonical JSON document. */
    public record Record(String id, Kind kind, String creator, String json) {
    }

    static final String GRAPH = "urn:x-lws:access";
    private static final String CREATOR = "urn:x-lws:accessCreator";
    private static final String JSON = "urn:x-lws:accessJson";

    private final RdfStore rdf;
    private final LwsConfiguration config;
    private final ResourceRegistry registry;

    /** Fast path: skip grant evaluation entirely when no grants exist. */
    private volatile boolean hasGrants;

    public AccessService(RdfStore rdf, LwsConfiguration config, ResourceRegistry registry) {
        this.rdf = rdf;
        this.config = config;
        this.registry = registry;
        this.hasGrants = countGrants() > 0;
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

    /** True if an active grant authorizes {@code principal} to perform {@code mode} on {@code iri}. */
    public boolean grants(LwsPrincipal principal, String iri, AclMode mode, Instant now) {
        if (mode == AclMode.CONTROL || !hasGrants) {
            return false; // grants never confer Control, and skip when there are none
        }
        List<String> documents = rdf.read(conn -> {
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            q.setCommandText("SELECT ?json WHERE { GRAPH ?g { ?s a ?t . ?s ?jsonP ?json } }");
            q.setIri("g", GRAPH);
            q.setIri("t", LWS.AccessGrant.getURI());
            q.setIri("jsonP", JSON);
            List<String> out = new ArrayList<>();
            conn.querySelect(q.asQuery(), row -> out.add(row.getLiteral("json").getString()));
            return out;
        });
        // Resource metadata (media type, types) is loaded once, on demand, only if a constraint needs it.
        TargetMetadata[] cache = new TargetMetadata[1];
        Supplier<TargetMetadata> target = () -> {
            if (cache[0] == null) {
                cache[0] = loadTargetMetadata(iri);
            }
            return cache[0];
        };
        for (String json : documents) {
            JsonObject doc = tryParse(json);
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

    private static boolean actionGrants(JsonObject policy, AclMode mode) {
        List<String> actions = strings(policy, "action");
        return switch (mode) {
            case READ -> actions.contains("read");
            case APPEND -> actions.contains("create");
            case WRITE -> actions.contains("modify") || actions.contains("delete");
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

    private static void validatePolicy(JsonObject policy) {
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
        try (var reader = Json.createReader(new ByteArrayInputStream(body))) {
            JsonStructure parsed = reader.read();
            if (parsed.getValueType() != JsonValue.ValueType.OBJECT) {
                throw LwsException.badRequest("Request body must be a JSON object");
            }
            return parsed.asJsonObject();
        } catch (JsonException | IllegalStateException e) {
            throw LwsException.badRequest("Invalid JSON: " + e.getMessage());
        }
    }

    private static JsonObject tryParse(String json) {
        try (var reader = Json.createReader(new java.io.StringReader(json))) {
            JsonStructure parsed = reader.read();
            return parsed.getValueType() == JsonValue.ValueType.OBJECT ? parsed.asJsonObject() : null;
        } catch (JsonException | IllegalStateException e) {
            return null;
        }
    }
}
