package com.ebremer.lws.server.core;

import java.io.StringReader;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.rdfconnection.RDFConnection;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Manages each resource's <em>linkset resource</em> (its metadata), per lws10-core and
 * <a href="https://www.rfc-editor.org/rfc/rfc9264">RFC 9264</a>. The linkset is served as
 * {@code application/linkset+json} and combines:
 * <ul>
 *   <li><strong>server-managed</strong> links — {@code type}, {@code up} (parent container),
 *       {@code linkset} (self) and the storage description — which are generated on every read and
 *       MUST NOT be overridden by clients; and</li>
 *   <li><strong>user-managed</strong> links — any other relations a client sets via PUT/PATCH on
 *       the linkset resource, persisted in a dedicated metadata graph.</li>
 * </ul>
 *
 * The user-managed portion is stored as a JSON object keyed by relation. A relation's value may be
 * an <strong>RFC 9264 target array</strong> (objects with {@code href} plus optional link attributes
 * such as {@code title}) or a <strong>literal</strong> (a JSON string or array, e.g. a {@code title}
 * or {@code creator} label) — both round-trip unchanged, so literal-valued core metadata is supported
 * even though RFC 9264 itself is href-based. It is updated by full replacement (PUT of a linkset
 * document), JSON Merge Patch (RFC 7386), JSON Patch (RFC 6902), or — via {@code Prefer: set-linkset}
 * on a resource write — the request's {@code Link} headers. It is removed when its resource is deleted.
 *
 * @author Erich Bremer
 */
public final class LinksetService implements ResourceEventListener {

    /** Named graph holding user-managed metadata, as one JSON literal per resource. */
    public static final String META_GRAPH = "urn:x-lws:linkset";
    private static final String USER_META = "urn:x-lws:userMetadata";

    /** Relations the server manages; a client cannot set or override these. */
    private static final Set<String> SERVER_MANAGED =
            Set.of("anchor", "type", "up", "linkset", LWS.NS + "storageDescription");

    private final RdfStore rdf;
    private final ResourceService resources;
    private final LwsConfiguration config;

    public LinksetService(RdfStore rdf, ResourceService resources, LwsConfiguration config) {
        this.rdf = rdf;
        this.resources = resources;
        this.config = config;
    }

    /** A serialized linkset and its entity-tag. */
    public record Linkset(String json, String etag) {
    }

    /** The full linkset (server-managed + user-managed) for an existing resource. */
    public Linkset get(String targetPath) {
        LwsResource meta = resources.stat(targetPath)
                .orElseThrow(() -> LwsException.notFound(targetPath));
        JsonObject user = readUserMetadata(meta.iri());
        String json = build(meta, user);
        return new Linkset(json, Etags.sha16(json));
    }

    /** Replace the user-managed links from a full {@code application/linkset+json} document. */
    public Linkset put(String targetPath, byte[] body) {
        LwsResource meta = resources.stat(targetPath)
                .orElseThrow(() -> LwsException.notFound(targetPath));
        JsonObject member = firstMember(parseObject(body));
        JsonObjectBuilder userBuilder = Json.createObjectBuilder();
        for (var entry : member.entrySet()) {
            if (!SERVER_MANAGED.contains(entry.getKey())) {
                userBuilder.add(entry.getKey(), entry.getValue());
            }
        }
        return store(meta, userBuilder.build());
    }

    /** Apply a JSON Merge Patch (RFC 7386) to the user-managed links. */
    public Linkset patch(String targetPath, byte[] body) {
        LwsResource meta = resources.stat(targetPath)
                .orElseThrow(() -> LwsException.notFound(targetPath));
        JsonValue patch;
        try {
            patch = JsonMergePatch.read(body);
        } catch (RuntimeException e) {
            throw LwsException.badRequest("Invalid JSON merge patch: " + e.getMessage());
        }
        JsonValue merged = JsonMergePatch.apply(readUserMetadata(meta.iri()), patch);
        JsonObject user = (merged.getValueType() == JsonValue.ValueType.OBJECT)
                ? merged.asJsonObject() : JsonValue.EMPTY_JSON_OBJECT;
        return store(meta, user);
    }

    /** Apply a JSON Patch (RFC 6902) to the user-managed links. */
    public Linkset jsonPatch(String targetPath, byte[] body) {
        LwsResource meta = resources.stat(targetPath)
                .orElseThrow(() -> LwsException.notFound(targetPath));
        JsonArray patch = JsonPatch.read(body);
        JsonStructure patched = JsonPatch.apply(readUserMetadata(meta.iri()), patch);
        JsonObject user = (patched.getValueType() == JsonValue.ValueType.OBJECT)
                ? patched.asJsonObject() : JsonValue.EMPTY_JSON_OBJECT;
        return store(meta, user);
    }

    /** Replace the user-managed links from parsed {@code Link} headers (Prefer: set-linkset on PUT). */
    public Linkset replaceFromLinks(String targetPath, Map<String, List<String>> links) {
        LwsResource meta = resources.stat(targetPath)
                .orElseThrow(() -> LwsException.notFound(targetPath));
        return store(meta, linksToUserObject(links));
    }

    /** Merge parsed {@code Link} headers into the user-managed links (Prefer: set-linkset on PATCH). */
    public Linkset mergeFromLinks(String targetPath, Map<String, List<String>> links) {
        LwsResource meta = resources.stat(targetPath)
                .orElseThrow(() -> LwsException.notFound(targetPath));
        JsonObjectBuilder merged = Json.createObjectBuilder(readUserMetadata(meta.iri()));
        linksToUserObject(links).forEach(merged::add); // each provided relation replaces that relation
        return store(meta, merged.build());
    }

    /**
     * Return the linkset JSON keeping only the {@code include} relations, or dropping the {@code omit}
     * relations (the structural {@code anchor} is always kept). Implements the LWS PreferLinkRelations
     * read preference; pass {@code include} when non-null, otherwise {@code omit}.
     */
    public static String filterRelations(String linksetJson, Set<String> include, Set<String> omit) {
        JsonObject doc;
        try (JsonReader r = Json.createReader(new StringReader(linksetJson))) {
            doc = r.readObject();
        }
        JsonObject member = doc.getJsonArray("linkset").getJsonObject(0);
        JsonObjectBuilder filtered = Json.createObjectBuilder();
        for (Map.Entry<String, JsonValue> entry : member.entrySet()) {
            String rel = entry.getKey();
            boolean keep = rel.equals("anchor")
                    || (include != null ? include.contains(rel) : !omit.contains(rel));
            if (keep) {
                filtered.add(rel, entry.getValue());
            }
        }
        return Json.createObjectBuilder()
                .add("linkset", Json.createArrayBuilder().add(filtered))
                .build().toString();
    }

    /** Build a user-metadata object (relation &rarr; href targets) from parsed Link headers. */
    private static JsonObject linksToUserObject(Map<String, List<String>> links) {
        JsonObjectBuilder user = Json.createObjectBuilder();
        for (Map.Entry<String, List<String>> entry : links.entrySet()) {
            if (SERVER_MANAGED.contains(entry.getKey())) {
                continue; // a client cannot set or override server-managed relations
            }
            JsonArrayBuilder targets = Json.createArrayBuilder();
            for (String href : entry.getValue()) {
                targets.add(Json.createObjectBuilder().add("href", href));
            }
            user.add(entry.getKey(), targets);
        }
        return user.build();
    }

    @Override
    public void onResourceEvent(ResourceEvent event) {
        // Deleting a resource removes its linkset metadata (lws10-core metadata lifecycle).
        if (event.kind() == ActivityKind.DELETE) {
            rdf.writeDo(conn -> deleteUserMetadata(conn, event.iri()));
        }
    }

    // ----- internals -----

    private Linkset store(LwsResource meta, JsonObject user) {
        rdf.writeDo(conn -> {
            deleteUserMetadata(conn, meta.iri());
            if (!user.isEmpty()) {
                ParameterizedSparqlString u = new ParameterizedSparqlString();
                u.setCommandText("INSERT DATA { GRAPH ?g { ?s ?p ?json } }");
                u.setIri("g", META_GRAPH);
                u.setIri("s", meta.iri());
                u.setIri("p", USER_META);
                u.setLiteral("json", user.toString());
                conn.update(u.asUpdate());
            }
        });
        String json = build(meta, user);
        return new Linkset(json, Etags.sha16(json));
    }

    private JsonObject readUserMetadata(String anchor) {
        return rdf.read(conn -> {
            ParameterizedSparqlString q = new ParameterizedSparqlString();
            q.setCommandText("SELECT ?json WHERE { GRAPH ?g { ?s ?p ?json } } LIMIT 1");
            q.setIri("g", META_GRAPH);
            q.setIri("s", anchor);
            q.setIri("p", USER_META);
            String[] holder = new String[1];
            conn.querySelect(q.asQuery(), row -> holder[0] = row.getLiteral("json").getString());
            if (holder[0] == null) {
                return JsonValue.EMPTY_JSON_OBJECT;
            }
            try (JsonReader reader = Json.createReader(new StringReader(holder[0]))) {
                return reader.readObject();
            } catch (JsonException | IllegalStateException e) {
                return JsonValue.EMPTY_JSON_OBJECT;
            }
        });
    }

    private void deleteUserMetadata(RDFConnection conn, String anchor) {
        ParameterizedSparqlString u = new ParameterizedSparqlString();
        u.setCommandText("DELETE WHERE { GRAPH ?g { ?s ?p ?json } }");
        u.setIri("g", META_GRAPH);
        u.setIri("s", anchor);
        u.setIri("p", USER_META);
        conn.update(u.asUpdate());
    }

    /** Render the RFC 9264 linkset document (server-managed links first, then user-managed). */
    private String build(LwsResource meta, JsonObject user) {
        JsonObjectBuilder anchor = Json.createObjectBuilder();
        anchor.add("anchor", meta.iri());
        anchor.add("type", hrefs(typeIri(meta)));
        if (meta.parentIri() != null) {
            anchor.add("up", hrefs(meta.parentIri()));
        }
        anchor.add("linkset", hrefs(Iris.linkset(meta.iri())));
        anchor.add(LWS.NS + "storageDescription", hrefs(config.storageDescriptionIri()));
        for (var entry : user.entrySet()) {
            if (!SERVER_MANAGED.contains(entry.getKey())) {
                anchor.add(entry.getKey(), entry.getValue());
            }
        }
        return Json.createObjectBuilder()
                .add("linkset", Json.createArrayBuilder().add(anchor))
                .build().toString();
    }

    private static String typeIri(LwsResource meta) {
        return (meta.type() == ResourceType.CONTAINER ? LWS.Container : LWS.DataResource).getURI();
    }

    private static JsonArray hrefs(String href) {
        return Json.createArrayBuilder().add(Json.createObjectBuilder().add("href", href)).build();
    }

    private static JsonObject parseObject(byte[] body) {
        try (JsonReader reader = Json.createReader(new java.io.ByteArrayInputStream(body))) {
            JsonStructure parsed = reader.read();
            if (parsed.getValueType() != JsonValue.ValueType.OBJECT) {
                throw LwsException.badRequest("Linkset document must be a JSON object");
            }
            return parsed.asJsonObject();
        } catch (JsonException | IllegalStateException e) {
            throw LwsException.badRequest("Invalid linkset document: " + e.getMessage());
        }
    }

    private static JsonObject firstMember(JsonObject doc) {
        JsonArray linkset = doc.containsKey("linkset") && doc.get("linkset").getValueType() == JsonValue.ValueType.ARRAY
                ? doc.getJsonArray("linkset") : null;
        if (linkset == null || linkset.isEmpty()) {
            return JsonValue.EMPTY_JSON_OBJECT;
        }
        JsonValue first = linkset.get(0);
        return first.getValueType() == JsonValue.ValueType.OBJECT ? first.asJsonObject() : JsonValue.EMPTY_JSON_OBJECT;
    }
}
