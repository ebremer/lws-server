package com.ebremer.lws.server.core;

import java.io.StringReader;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
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
import com.ebremer.lws.server.vocab.LDP;
import com.ebremer.lws.server.vocab.LWS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
public final class LinksetService implements ResourceCleanup {

    private static final Logger log = LoggerFactory.getLogger(LinksetService.class);

    /** Named graph holding user-managed metadata, as one JSON literal per resource. */
    public static final String META_GRAPH = "urn:x-lws:linkset";
    private static final String USER_META = "urn:x-lws:userMetadata";

    /** Relations the server manages; a client cannot set or override these. */
    private static final Set<String> SERVER_MANAGED =
            Set.of("anchor", "up", "linkset", LWS.NS + "storageDescription");

    /**
     * The one relation a client may <em>add</em> to without being able to override it.
     *
     * <p>{@code type} used to be flatly server-managed, which closed off the searchindex spec's
     * preferred way of declaring what a resource is: a client had no way at all to say that its
     * document is a {@code schema:Person}, and for a binary resource — which has no content graph to
     * assert it in — no way existed anywhere. It is not really a server relation and not really a
     * client one: the server always knows the resource's structural type, and the client knows what
     * the thing is about. So both are emitted, the server's first.
     *
     * <p>What a client may declare is bounded by {@link #declarableType}: nothing in the LWS
     * namespace and none of the LDP interaction models. That is the whole security argument. A type
     * is descriptive metadata the client already controls for its own resource, gated by the same
     * write permission as the content — with one exception, the types this server assigns and
     * consults itself, which a client asserting would be spoofing rather than describing.
     */
    private static final Set<String> SERVER_AUGMENTED = Set.of("type");

    /**
     * The interaction models, which name what a resource <em>is to this server</em> rather than what
     * it is about. A client declaring one would be claiming to be a container.
     */
    private static final Set<String> INTERACTION_MODELS = Set.of(
            LDP.RESOURCE, LDP.CONTAINER, LDP.BASIC_CONTAINER, LDP.RDF_SOURCE, LDP.NON_RDF_SOURCE);

    /**
     * Whether a client may declare {@code iri} as one of its resource's types.
     *
     * <p>The LWS namespace is refused wholesale rather than by a hand-written list of terms. A list
     * would have to contain {@code lws:Container} and {@code lws:DataResource} — and also
     * {@code lws:Storage}, {@code lws:StorageDescription}, {@code lws:AccessGrant},
     * {@code lws:TypeIndexService} and every term minted after it was written. A denylist over a
     * namespace somebody else extends is a denylist that goes stale; refusing the namespace does not.
     */
    static boolean declarableType(String iri) {
        return iri != null && SearchIndexService.isAbsoluteUri(iri)
                && !iri.startsWith(LWS.NS) && !INTERACTION_MODELS.contains(iri);
    }

    /**
     * Keep only the relation values a client is allowed to set: everything except server-managed
     * relations, and — for {@code type} — only IRIs that pass {@link #declarableType}.
     */
    /**
     * Whether {@code relation} names one of the server-managed relations.
     *
     * <p>Case-insensitively, because RFC 8288 §3.3 says a registered relation type is compared
     * case-insensitively — so {@code Anchor} and {@code UP} are the same relation as {@code anchor}
     * and {@code up}. Matching exactly let a client store an {@code Anchor} of its own choosing,
     * which the renderer then emitted alongside the server's real {@code anchor}: one document
     * asserting two different subjects, with the client's copy indistinguishable from the server's
     * to any consumer that lower-cases relation names, as a conforming one must.
     */
    private static boolean isServerRelation(Set<String> relations, String relation) {
        for (String managed : relations) {
            if (managed.equalsIgnoreCase(relation)) {
                return true;
            }
        }
        return false;
    }

    private static JsonObject sanitizeUserRelations(JsonObject candidate) {
        JsonObjectBuilder kept = Json.createObjectBuilder();
        for (Map.Entry<String, JsonValue> entry : candidate.entrySet()) {
            if (isServerRelation(SERVER_MANAGED, entry.getKey())) {
                continue;
            }
            if (isServerRelation(SERVER_AUGMENTED, entry.getKey())) {
                JsonArray allowed = declarableTargets(entry.getValue());
                if (!allowed.isEmpty()) {
                    kept.add(entry.getKey(), allowed);
                }
                continue;
            }
            kept.add(entry.getKey(), entry.getValue());
        }
        return kept.build();
    }

    /** The {@code href} targets of a link-target array that a client may declare as a type. */
    private static JsonArray declarableTargets(JsonValue value) {
        JsonArrayBuilder out = Json.createArrayBuilder();
        if (value.getValueType() != JsonValue.ValueType.ARRAY) {
            return out.build();
        }
        for (JsonValue target : value.asJsonArray()) {
            if (target.getValueType() != JsonValue.ValueType.OBJECT) {
                continue;
            }
            String href = target.asJsonObject().getString("href", null);
            if (declarableType(href)) {
                out.add(Json.createObjectBuilder().add("href", href));
            }
        }
        return out.build();
    }

    /** The types a client has declared for a resource, read straight from its stored metadata. */
    public Set<String> declaredTypes(RDFConnection conn, String iri) {
        JsonValue types = readUserMetadata(conn, iri).get("type");
        Set<String> out = new java.util.LinkedHashSet<>();
        if (types == null || types.getValueType() != JsonValue.ValueType.ARRAY) {
            return out;
        }
        for (JsonValue target : types.asJsonArray()) {
            if (target.getValueType() == JsonValue.ValueType.OBJECT) {
                String href = target.asJsonObject().getString("href", null);
                if (declarableType(href)) {
                    out.add(href);
                }
            }
        }
        return out;
    }

    /** Every resource that has declared types, for the search index's one-time build. */
    public Map<String, Set<String>> allDeclaredTypes(RDFConnection conn) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("SELECT ?s ?json WHERE { GRAPH ?g { ?s ?p ?json } }");
        q.setIri("g", META_GRAPH);
        q.setIri("p", USER_META);
        Map<String, Set<String>> out = new java.util.HashMap<>();
        conn.querySelect(q.asQuery(), row -> {
            Set<String> types = typesOf(row.getLiteral("json").getString());
            if (!types.isEmpty()) {
                out.put(row.getResource("s").getURI(), types);
            }
        });
        return out;
    }

    private static Set<String> typesOf(String json) {
        Set<String> out = new java.util.LinkedHashSet<>();
        try {
            // Bounded before parsing, and the catch widened, for the reason recorded on
            // readUserMetadata. This one runs from allDeclaredTypes over EVERY stored linkset, so
            // without it a single poisoned resource failed the search-index build for the whole
            // storage rather than only its own read.
            JsonLimits.requireBoundedNesting(json, JsonLimits.MAX_NESTING_DEPTH);
            try (JsonReader reader = Json.createReader(new StringReader(json))) {
                JsonValue types = reader.readObject().get("type");
                if (types != null && types.getValueType() == JsonValue.ValueType.ARRAY) {
                    for (JsonValue target : types.asJsonArray()) {
                        if (target.getValueType() == JsonValue.ValueType.OBJECT) {
                            String href = target.asJsonObject().getString("href", null);
                            if (declarableType(href)) {
                                out.add(href);
                            }
                        }
                    }
                }
            }
        } catch (RuntimeException | StackOverflowError e) {
            return out;
        }
        return out;
    }

    /**
     * Told after every metadata write, so a derived index over declared types can be refreshed.
     * Set by the wiring; never null after construction.
     */
    private volatile java.util.function.Consumer<String> metadataListener = iri -> { };

    /** Register the listener told when a resource's user-managed metadata changes. */
    public void setMetadataListener(java.util.function.Consumer<String> listener) {
        this.metadataListener = listener == null ? iri -> { } : listener;
    }

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

    /**
     * The full linkset (server-managed + user-managed) for an existing resource.
     *
     * <p>Read in a single transaction. The resource metadata and the user-managed links are both
     * ingredients of the entity-tag this hands out, and reading them separately could produce a tag
     * for a state that never existed &mdash; a tag no conditional write could then ever match.
     */
    public Linkset get(String targetPath) {
        return rdf.read(conn -> {
            LwsResource meta = resources.stat(conn, targetPath)
                    .orElseThrow(() -> LwsException.notFound(targetPath));
            return render(meta, readUserMetadata(conn, meta.iri()));
        });
    }

    /** Replace the user-managed links from a full {@code application/linkset+json} document. */
    public Linkset put(String targetPath, byte[] body) {
        return put(targetPath, body, IfMatch.NONE);
    }

    /** Replace the user-managed links, honouring the client {@code If-Match} precondition. */
    public Linkset put(String targetPath, byte[] body, IfMatch ifMatch) {
        JsonObject replacement = sanitizeUserRelations(firstMember(parseObject(body)));
        return update(targetPath, ifMatch, current -> replacement);
    }

    /** Apply a JSON Merge Patch (RFC 7386) to the user-managed links. */
    public Linkset patch(String targetPath, byte[] body) {
        return patch(targetPath, body, IfMatch.NONE);
    }

    /** Apply a JSON Merge Patch, honouring the client {@code If-Match} precondition. */
    public Linkset patch(String targetPath, byte[] body, IfMatch ifMatch) {
        JsonValue patch;
        try {
            patch = JsonMergePatch.read(body);
        } catch (RuntimeException e) {
            throw LwsException.badRequest("Invalid JSON merge patch: " + e.getMessage());
        }
        return update(targetPath, ifMatch,
                current -> sanitizeUserRelations(asObject(JsonMergePatch.apply(current, patch))));
    }

    /** Apply a JSON Patch (RFC 6902) to the user-managed links. */
    public Linkset jsonPatch(String targetPath, byte[] body) {
        return jsonPatch(targetPath, body, IfMatch.NONE);
    }

    /** Apply a JSON Patch, honouring the client {@code If-Match} precondition. */
    public Linkset jsonPatch(String targetPath, byte[] body, IfMatch ifMatch) {
        JsonArray patch = JsonPatch.read(body);
        return update(targetPath, ifMatch,
                current -> sanitizeUserRelations(asObject(JsonPatch.apply(current, patch))));
    }

    /** Replace the user-managed links from parsed {@code Link} headers (Prefer: set-linkset on PUT). */
    public Linkset replaceFromLinks(String targetPath, Map<String, List<String>> links) {
        JsonObject replacement = linksToUserObject(links);
        return update(targetPath, IfMatch.NONE, current -> replacement);
    }

    /** Merge parsed {@code Link} headers into the user-managed links (Prefer: set-linkset on PATCH). */
    public Linkset mergeFromLinks(String targetPath, Map<String, List<String>> links) {
        return update(targetPath, IfMatch.NONE, current -> {
            JsonObjectBuilder merged = Json.createObjectBuilder(current);
            linksToUserObject(links).forEach(merged::add); // each provided relation replaces that relation
            return merged.build();
        });
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
        } catch (RuntimeException | StackOverflowError e) {
            // Defence in depth: the argument is a document this server has just rendered from a
            // bounded object, so this is unreachable once update() holds. It must not fall back to
            // returning the document unfiltered — that would hand back exactly the relations the
            // client asked to omit.
            throw new LwsException(500, "Linkset could not be filtered");
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
            JsonArrayBuilder targets = Json.createArrayBuilder();
            for (String href : entry.getValue()) {
                targets.add(Json.createObjectBuilder().add("href", href));
            }
            user.add(entry.getKey(), targets);
        }
        // One sanitizer for every path in: server-managed relations dropped, and a declared `type`
        // reduced to the IRIs a client may actually claim.
        return sanitizeUserRelations(user.build());
    }

    /**
     * Deleting a resource removes its linkset metadata (lws10-core metadata lifecycle) &mdash; in
     * the transaction that deletes the resource, rather than a later one of its own. See
     * {@link ResourceCleanup}.
     */
    @Override
    public void onDelete(RDFConnection conn, String iri) {
        deleteUserMetadata(conn, iri);
    }

    // ----- internals -----

    /**
     * Read the user-managed links, apply {@code mutation} to them and store the result &mdash; the
     * whole read-modify-write in one transaction, with the precondition compared inside it.
     *
     * <p>It used to span three: {@code enforceLinksetPrecondition} read the current tag in one, the
     * patch read the stored links in a second, and the write opened a third. Two clients holding
     * the same valid tag therefore both passed and both wrote, and the last one won (finding M18).
     *
     * <p>The mutation is a pure, CPU-bound function of the stored links, which is what makes it safe
     * to run with the writer lock held: the store admits one writer for the whole storage, so
     * anything that <em>blocks</em> in here stalls every other write (finding H16). Parsing the
     * client's patch and bounding its nesting are already done by the time this is called; applying
     * it can still fail on a bad JSON Pointer, which simply aborts the transaction.
     */
    private Linkset update(String targetPath, IfMatch ifMatch, UnaryOperator<JsonObject> mutation) {
        // Told after the transaction commits, not inside it: the listener maintains a derived index
        // and must not see a write that then rolls back.
        String[] changed = new String[1];
        Linkset result = rdf.write(conn -> {
            LwsResource meta = resources.stat(conn, targetPath)
                    .orElseThrow(() -> LwsException.notFound(targetPath));
            JsonObject current = readUserMetadata(conn, meta.iri());
            if (!ifMatch.matches(render(meta, current).etag())) {
                throw LwsException.preconditionFailed("Precondition Failed");
            }
            // Sanitized HERE, not at each caller. Every mutation already sanitizes its own input,
            // but this is the single point every one of them passes through, and a bound that
            // depends on five callers each remembering is a bound one new caller removes.
            JsonObject user = sanitizeUserRelations(mutation.apply(current));
            // Finding N5. The request-body guard bounds one request and does not compose: a patch
            // that is itself shallow is applied to what is already stored and deepens it, so
            // repeating it grows the stored linkset without limit while every individual request
            // stays comfortably inside the bound — until nothing can parse what is stored, the
            // owner included. And a JSON Patch `copy` from "" doubles the document per request
            // while adding only one level, so depth alone is not enough; the size goes with it.
            //
            // Checked on the tree, and BEFORE the toString() below rather than on its bytes: that
            // toString() is the JSON provider's own recursive generator, so producing bytes to
            // hand to the byte-oriented guard would overflow the stack on exactly the documents
            // worth refusing. Before the DELETE too — the transaction would roll that back, but a
            // refusal that has already issued a DELETE has spent it under the writer lock.
            //
            // MAX_NESTING_DEPTH - 2, not MAX_NESTING_DEPTH: build() wraps this object in the
            // linkset array and its member object, so a `user` at the full depth would render a
            // document two levels past what parseObject accepts on the way back in — the server
            // would hand out a linkset it then refuses to be given.
            JsonLimits.requireBounded(user, JsonLimits.MAX_NESTING_DEPTH - 2,
                    config.linksetMaxBytes(), "Stored linkset metadata would be");
            String serialized = user.isEmpty() ? null : user.toString();
            if (serialized != null && JsonLimits.utf8Length(serialized) > config.linksetMaxBytes()) {
                throw LwsException.badRequest("Stored linkset metadata would be larger than "
                        + config.linksetMaxBytes() + " bytes");
            }
            deleteUserMetadata(conn, meta.iri());
            if (serialized != null) {
                ParameterizedSparqlString u = new ParameterizedSparqlString();
                u.setCommandText("INSERT DATA { GRAPH ?g { ?s ?p ?json } }");
                u.setIri("g", META_GRAPH);
                u.setIri("s", meta.iri());
                u.setIri("p", USER_META);
                u.setLiteral("json", serialized);
                conn.update(u.asUpdate());
            }
            Linkset rendered = render(meta, user);
            changed[0] = meta.iri();
            return rendered;
        });
        if (changed[0] != null) {
            metadataListener.accept(changed[0]);
        }
        return result;
    }

    /** The rendered linkset document and its entity-tag. */
    private Linkset render(LwsResource meta, JsonObject user) {
        String json = build(meta, user);
        return new Linkset(json, Etags.sha16(json));
    }

    private static JsonObject asObject(JsonValue value) {
        return value.getValueType() == JsonValue.ValueType.OBJECT
                ? value.asJsonObject() : JsonValue.EMPTY_JSON_OBJECT;
    }

    private JsonObject readUserMetadata(RDFConnection conn, String anchor) {
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
        try {
            // Guard first, so the parser never sees a document it cannot survive — the same order
            // JsonLimits was written for. This is the backstop for anything stored before the
            // write-side bound existed (finding N5); the control is the bound in update().
            JsonLimits.requireBoundedNesting(holder[0], JsonLimits.MAX_NESTING_DEPTH);
            try (JsonReader reader = Json.createReader(new StringReader(holder[0]))) {
                return reader.readObject();
            }
        } catch (RuntimeException | StackOverflowError e) {
            // RuntimeException, not just JsonException: the provider on this classpath enforces its
            // own nesting cap and reports it as a bare java.lang.RuntimeException, which the
            // previous catch let through as a 500 on every read of the resource, for everyone
            // including its owner. Degrading to "no user-managed links" is the same degradation
            // this already applied to a literal that would not parse, and it is what makes the
            // repair path work: update() reads through here first, so without it a poisoned
            // linkset could not even be overwritten by a PUT. Warned, because silently dropping
            // stored metadata is not something to discover from a diff.
            log.warn("Stored linkset metadata for {} could not be read and was ignored: {}",
                    anchor, e.toString());
            return JsonValue.EMPTY_JSON_OBJECT;
        }
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
        // The structural type this server assigns, then any the client has declared. Both are types
        // of the anchor, which is what RFC 9264's `type` relation means; the server's is always
        // present and always first, so a declared type can add to the picture and never replace it.
        anchor.add("type", allTypes(meta, user));
        if (meta.parentIri() != null) {
            anchor.add("up", hrefs(meta.parentIri()));
        }
        anchor.add("linkset", hrefs(Iris.linkset(meta.iri())));
        anchor.add(LWS.NS + "storageDescription", hrefs(config.storageDescriptionIri()));
        for (var entry : user.entrySet()) {
            if (!isServerRelation(SERVER_MANAGED, entry.getKey())
                    && !isServerRelation(SERVER_AUGMENTED, entry.getKey())) {
                anchor.add(entry.getKey(), entry.getValue());
            }
        }
        return Json.createObjectBuilder()
                .add("linkset", Json.createArrayBuilder().add(anchor))
                .build().toString();
    }

    /** The server's structural type for a resource, followed by any the client has declared. */
    private static JsonArray allTypes(LwsResource meta, JsonObject user) {
        JsonArrayBuilder out = Json.createArrayBuilder();
        out.add(Json.createObjectBuilder().add("href", typeIri(meta)));
        JsonValue declared = user.get("type");
        if (declared != null && declared.getValueType() == JsonValue.ValueType.ARRAY) {
            for (JsonValue target : declared.asJsonArray()) {
                if (target.getValueType() == JsonValue.ValueType.OBJECT) {
                    String href = target.asJsonObject().getString("href", null);
                    if (declarableType(href)) {
                        out.add(Json.createObjectBuilder().add("href", href));
                    }
                }
            }
        }
        return out.build();
    }

    private static String typeIri(LwsResource meta) {
        return (meta.type() == ResourceType.CONTAINER ? LWS.Container : LWS.DataResource).getURI();
    }

    private static JsonArray hrefs(String href) {
        return Json.createArrayBuilder().add(Json.createObjectBuilder().add("href", href)).build();
    }

    private static JsonObject parseObject(byte[] body) {
        JsonLimits.requireBoundedNesting(body);
        try (JsonReader reader = Json.createReader(new java.io.ByteArrayInputStream(body))) {
            JsonStructure parsed = reader.read();
            if (parsed.getValueType() != JsonValue.ValueType.OBJECT) {
                throw LwsException.badRequest("Linkset document must be a JSON object");
            }
            return parsed.asJsonObject();
        } catch (JsonException | IllegalStateException | StackOverflowError e) {
            throw LwsException.badRequest("Invalid linkset document: " + e);
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
