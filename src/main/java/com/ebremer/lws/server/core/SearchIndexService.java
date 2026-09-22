package com.ebremer.lws.server.core;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.rdfconnection.RDFConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Implements the LWS Type Index and Type Search services, per
 * <a href="https://w3c.github.io/lws-protocol/lws10-index/">LWS Search and Type Index Services</a>
 * (lws10-index, formerly lws10-searchindex).
 *
 * <p>A resource's <em>types</em> are derived from two sources, treated identically:
 * <ul>
 *   <li>its <strong>structural</strong> LWS type — {@code lws:Container} or {@code lws:DataResource}
 *       — which the server always knows (and advertises via {@code Link: rel="type"}); and</li>
 *   <li>any {@code rdf:type} the resource's own representation asserts about itself (the resource
 *       IRI or one of its hash fragments).</li>
 * </ul>
 *
 * <p>An optional descriptive <em>relation</em> filter matches resources that link to a target via a
 * given relation. The key is a registered relation name (RFC 8288) or, for an extension relation,
 * its URI, and the targets come from every source lws10-index names, treated identically: the links
 * the client declared in the resource's metadata (its {@code Link} headers and linkset) for either
 * kind of key, and — for a URI key — the triples the resource's own representation asserts with that
 * predicate. Structural and protocol relations are never answered: the server-managed links are
 * refused by the linkset service, and the administrative graph is never read. A relation the server
 * does not index yields no matches, indistinguishably from a target nothing declares.
 *
 * <p>Resource <em>types</em> are served from an in-memory derived index, built lazily on first use
 * and maintained incrementally from resource events. Type/relation membership may therefore be
 * eventually consistent (a bounded allowance lws10-searchindex grants for derivation); because events
 * are delivered synchronously on the writing thread, read-your-writes still holds in practice.
 *
 * <p>Every response is filtered against the requesting principal's <em>current</em> read
 * authorization: a type or resource the client cannot read never appears, and {@code totalItems} is
 * counted over that authorization-filtered view. Authorization is <strong>never</strong> cached — it
 * is applied live, per request, over the derived index, so a revoked grant takes effect immediately
 * (the spec's eventual-consistency allowance applies only to derivation, never to authorization).
 *
 * @author Erich Bremer
 */
public final class SearchIndexService implements ResourceEventListener {

    private static final Logger log = LoggerFactory.getLogger(SearchIndexService.class);

    private final RdfStore rdfStore;
    private final Authorizer authorizer;
    /**
     * The resource metadata a client writes, which may declare types of its own (lws10-searchindex
     * treats {@code Link: rel="type"} as the preferred type source). Optional: a search index with no
     * linkset service simply indexes the structural and content-asserted types, as it always did.
     */
    private volatile LinksetService linksets;

    // Derived index: resource IRI -> its type set (structural + content-asserted). Built lazily by a
    // full scan and maintained incrementally by onResourceEvent. This is a complete materialized view,
    // NOT an evictable cache: every indexed resource must be present, so it is deliberately unbounded
    // with no TTL — bounding/evicting it would silently drop resources from search results. Its size
    // tracks the resource count (the in-memory-index trade-off noted for very large stores); it is not
    // a roll-your-own bounded cache like the auth/ACME caches (those use Caffeine). Relation targets
    // are NOT cached (unbounded across predicates) and are queried on demand per search.
    private final ConcurrentMap<String, Set<String>> typeCache = new ConcurrentHashMap<>();
    private final Object buildLock = new Object();
    private volatile boolean built;

    public SearchIndexService(RdfStore rdfStore, Authorizer authorizer) {
        this.rdfStore = rdfStore;
        this.authorizer = authorizer;
    }

    /**
     * Supply the metadata service whose client-declared types this index should include.
     *
     * <p>Set after construction because the two are mutually dependent: the linkset service is built
     * on top of the resource service, which is built with the authorizer this index also takes.
     */
    public void setLinksets(LinksetService linksets) {
        this.linksets = linksets;
    }

    /**
     * Recompute one resource's types after its metadata changed. Called by {@link LinksetService}
     * once its write has committed; without it a declared type would not appear in a search until
     * something else touched the resource.
     */
    public void onMetadataChanged(String iri) {
        synchronized (buildLock) {
            if (!built) {
                return;
            }
            try {
                Set<String> types = rdfStore.read(conn -> loadTypesFor(conn, iri, structuralOf(conn, iri)));
                if (types.isEmpty()) {
                    typeCache.remove(iri);
                } else {
                    typeCache.put(iri, Set.copyOf(types));
                }
            } catch (RuntimeException e) {
                built = false;
                log.warn("Type index update failed for {} after a metadata change; the index will be "
                        + "rebuilt on next use: {}", iri, e.toString());
            }
        }
    }

    /** A resource's structural type as the registry records it, or null if it is not registered. */
    private static ResourceType structuralOf(RDFConnection conn, String iri) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("SELECT ?t WHERE { GRAPH ?g { ?s a ?t } } LIMIT 1");
        q.setIri("g", ResourceRegistry.ADMIN_GRAPH);
        q.setIri("s", iri);
        ResourceType[] holder = new ResourceType[1];
        conn.querySelect(q.asQuery(), row ->
                holder[0] = row.getResource("t").getURI().equals(LWS.Container.getURI())
                        ? ResourceType.CONTAINER : ResourceType.RDF_SOURCE);
        return holder[0];
    }

    /** One conjunct of a query: the resource must bear at least one of {@code anyOf}. */
    public record Clause(String relation, List<String> anyOf) {

        /** A type clause (the mandatory baseline filter). */
        public static Clause type(List<String> anyOf) {
            return new Clause(null, List.copyOf(anyOf));
        }

        /** A descriptive-relation clause over the predicate {@code relation}. */
        public static Clause relation(String relation, List<String> anyOf) {
            return new Clause(relation, List.copyOf(anyOf));
        }

        public boolean isType() {
            return relation == null;
        }
    }

    /** A conjunctive-normal-form filter: a resource matches when it satisfies every clause. */
    public record Filter(List<Clause> clauses) {

        public static final Filter MATCH_ALL = new Filter(List.of());

        public Filter {
            clauses = List.copyOf(clauses);
        }

        public boolean isEmpty() {
            return clauses.isEmpty();
        }
    }

    /** A matched resource: its IRI and its full type set (structural type first, then sorted). */
    public record Match(String iri, List<String> types) {
    }

    /** One page of a paginated result set. */
    public record Page<T>(List<T> items, int totalItems, int page, int pageSize, int pages) {

        /** True if {@code page} is beyond the last page (the client used a stale page reference). */
        public boolean isOutOfRange() {
            return page > pages;
        }
    }

    /** The distinct resource types visible to {@code principal}, as a paginated list of type IRIs. */
    public Page<String> typeIndex(LwsPrincipal principal, int page, int pageSize) {
        // Same shape as a container listing and the same cost: one authorization decision per
        // indexed resource, on an endpoint that takes no filter to bound it. Where the answer cannot
        // vary by resource, skip the loop (findings M23/M39 applied to the second branch).
        boolean all = authorizer.allowsEverything(principal, AclMode.READ);
        TreeSet<String> visible = new TreeSet<>();
        for (Map.Entry<String, Set<String>> e : typeView().entrySet()) {
            if (all || authorizer.allows(principal, e.getKey(), AclMode.READ)) {
                visible.addAll(e.getValue());
            }
        }
        return paginate(new ArrayList<>(visible), page, pageSize);
    }

    /**
     * The resources matching {@code filter} that {@code principal} may read, paginated.
     *
     * <p>A filter with no clauses matches every resource the caller may read. This server used to
     * refuse it, when the draft made the type clause mandatory; lws10-index now says in so many
     * words that a request with no type key and no relation keys "matches all resources visible to
     * the client". It stays safe for the reason it always was: every match is
     * authorization-filtered and {@code totalItems} counts only the permitted view.
     */
    public Page<Match> typeSearch(LwsPrincipal principal, Filter filter, int page, int pageSize) {
        Map<String, Set<String>> typesByResource = typeView();
        Set<String> relationPredicates = filter.clauses().stream()
                .filter(c -> !c.isType())
                .map(Clause::relation)
                .collect(Collectors.toSet());
        Map<String, Map<String, Set<String>>> relations = relationPredicates.isEmpty()
                ? Map.of()
                : rdfStore.read(conn -> loadRelations(conn, relationPredicates, typesByResource.keySet()));

        boolean all = authorizer.allowsEverything(principal, AclMode.READ);
        List<Match> matches = new ArrayList<>();
        for (Map.Entry<String, Set<String>> e : typesByResource.entrySet()) {
            String iri = e.getKey();
            Set<String> types = e.getValue();
            // The filter first, deliberately: it is a set operation over an in-memory map, so the
            // authorization decision — the expensive half — is only reached for a resource that
            // would otherwise have been returned.
            if (matches(filter, iri, types, relations)
                    && (all || authorizer.allows(principal, iri, AclMode.READ))) {
                matches.add(new Match(iri, orderTypes(types)));
            }
        }
        matches.sort(Comparator.comparing(Match::iri));
        return paginate(matches, page, pageSize);
    }

    /**
     * Whether {@code value} matches the IRI production of RFC 3987 — an absolute IRI, optionally
     * with a fragment — which is what lws10-index requires of every type and relation target in a
     * filter; anything else is refused with {@code 400}.
     */
    public static boolean isAbsoluteIri(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            // Excluded from RFC 3987 outright: controls, space and the delimiters it never allows.
            if (c <= 0x20 || c == 0x7f || "<>\"{}|\\^`".indexOf(c) >= 0) {
                return false;
            }
        }
        try {
            // isReference, not isAbsolute: Jena's isAbsolute is RFC 3986's absolute-URI, which has
            // no fragment — and lws10-index allows one ("an absolute IRI, optionally carrying a
            // fragment identifier, the form of every IRI in the RDF abstract syntax").
            return org.apache.jena.irix.IRIx.create(value).isReference();
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** A syntactically valid absolute URI (has a scheme), e.g. an {@code http(s)} IRI. */
    public static boolean isAbsoluteUri(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        try {
            return new URI(value).isAbsolute();
        } catch (URISyntaxException e) {
            return false;
        }
    }

    // ----- matching -----

    private static boolean matches(Filter filter, String iri, Set<String> types,
            Map<String, Map<String, Set<String>>> relations) {
        for (Clause clause : filter.clauses()) {
            if (clause.isType()) {
                if (Collections.disjoint(types, clause.anyOf())) {
                    return false;
                }
            } else {
                // A relation we do not index (non-absolute predicate, or no data) yields no match.
                Map<String, Set<String>> byResource = relations.get(clause.relation());
                Set<String> targets = byResource == null ? null : byResource.get(iri);
                if (targets == null || Collections.disjoint(targets, clause.anyOf())) {
                    return false;
                }
            }
        }
        return true;
    }

    private static List<String> orderTypes(Set<String> types) {
        List<String> ordered = new ArrayList<>();
        for (String structural : List.of(LWS.Container.getURI(), LWS.DataResource.getURI())) {
            if (types.contains(structural)) {
                ordered.add(structural);
            }
        }
        types.stream().filter(t -> !ordered.contains(t)).sorted().forEach(ordered::add);
        return ordered;
    }

    private static <T> Page<T> paginate(List<T> all, int page, int pageSize) {
        int total = all.size();
        int pages = Math.max(1, (int) Math.ceil(total / (double) pageSize));
        int from = (page - 1) * pageSize;
        List<T> items = (from >= 0 && from < total)
                ? List.copyOf(all.subList(from, Math.min(from + pageSize, total)))
                : List.of();
        return new Page<>(items, total, page, pageSize, pages);
    }

    // ----- derived index (cache) -----

    /**
     * The current type view (resource IRI &rarr; type set), built lazily on first use. The returned
     * map is the live cache; callers only iterate it (values are immutable per-resource snapshots).
     */
    private Map<String, Set<String>> typeView() {
        if (!built) {
            synchronized (buildLock) {
                if (!built) {
                    Map<String, Set<String>> all = rdfStore.read(this::loadAllTypes);
                    typeCache.clear();
                    all.forEach((iri, types) -> typeCache.put(iri, Set.copyOf(types)));
                    built = true;
                }
            }
        }
        return typeCache;
    }

    /**
     * Maintain the derived index as resources change. Synchronised on {@link #buildLock} so an update
     * cannot interleave with the one-time build (an event arriving before the build is dropped — the
     * build then reads current store state, including that write — and one arriving after applies
     * incrementally). Authorization is unaffected: it is always evaluated live, per request.
     */
    @Override
    public void onResourceEvent(ResourceEvent event) {
        synchronized (buildLock) {
            if (!built) {
                return;
            }
            try {
                if (event.kind() == ActivityKind.DELETE) {
                    typeCache.remove(event.iri());
                } else {
                    Set<String> types = rdfStore.read(conn -> loadTypesFor(conn, event.iri(), event.type()));
                    typeCache.put(event.iri(), Set.copyOf(types));
                }
            } catch (RuntimeException e) {
                // The fan-out swallows what escapes here, so an update that failed would otherwise
                // leave this one resource wrong in the cache for the life of the process: `built` is
                // a one-way latch and nothing ever revisits it. Drop the whole index instead and let
                // the next read rebuild it from the store — the expensive, always-correct answer is
                // strictly better than a cheap permanently-wrong one.
                built = false;
                log.warn("Type index update failed for {}; the index will be rebuilt on next use: {}",
                        event.iri(), e.toString());
            }
        }
    }

    /** Full scan: each resource's structural type (admin graph) plus the types it asserts about itself. */
    private Map<String, Set<String>> loadAllTypes(RDFConnection conn) {
        Map<String, Set<String>> types = new HashMap<>();
        ParameterizedSparqlString admin = new ParameterizedSparqlString();
        admin.setCommandText("SELECT ?s ?t WHERE { GRAPH ?g { ?s a ?t } }");
        admin.setIri("g", ResourceRegistry.ADMIN_GRAPH);
        conn.querySelect(admin.asQuery(), row ->
                types.computeIfAbsent(row.getResource("s").getURI(), k -> new HashSet<>())
                        .add(row.getResource("t").getURI()));

        ParameterizedSparqlString content = new ParameterizedSparqlString();
        content.setCommandText("""
                SELECT DISTINCT ?g ?t WHERE {
                  GRAPH ?g { ?s a ?t }
                  FILTER( sameTerm(?s, ?g) || STRSTARTS(STR(?s), CONCAT(STR(?g), "#")) )
                }""");
        conn.querySelect(content.asQuery(), row -> {
            String g = row.getResource("g").getURI();
            Set<String> rt = types.get(g);
            if (rt != null && row.get("t").isURIResource()) {
                rt.add(row.getResource("t").getURI());
            }
        });

        // And the types the client declared in the resource's own metadata, which is the
        // searchindex spec's preferred source and the only one a binary resource has.
        LinksetService meta = linksets;
        if (meta != null) {
            meta.allDeclaredTypes(conn).forEach((iri, declared) -> {
                Set<String> rt = types.get(iri);
                if (rt != null) {
                    rt.addAll(declared);
                }
            });
        }
        return types;
    }

    /** Recompute one resource's type set: its structural type plus the types it asserts about itself. */
    private Set<String> loadTypesFor(RDFConnection conn, String iri, ResourceType structural) {
        Set<String> types = new HashSet<>();
        if (structural != null) {
            types.add((structural == ResourceType.CONTAINER ? LWS.Container : LWS.DataResource).getURI());
        }
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("""
                SELECT DISTINCT ?t WHERE {
                  GRAPH ?g { ?s a ?t }
                  FILTER( isIRI(?t) && ( sameTerm(?s, ?g) || STRSTARTS(STR(?s), CONCAT(STR(?g), "#")) ) )
                }""");
        q.setIri("g", iri);
        conn.querySelect(q.asQuery(), row -> types.add(row.getResource("t").getURI()));
        LinksetService meta = linksets;
        if (meta != null) {
            types.addAll(meta.declaredTypes(conn, iri));
        }
        return types;
    }

    /**
     * Relation targets for the given relation keys, restricted to known resources: the links each
     * resource's metadata declares for the relation, plus — for a key that is a URI — the objects
     * its own representation asserts with that predicate.
     */
    private Map<String, Map<String, Set<String>>> loadRelations(RDFConnection conn,
            Set<String> predicates, Set<String> resources) {
        Map<String, Map<String, Set<String>>> relations = new HashMap<>();
        LinksetService meta = linksets;
        for (String predicate : predicates) {
            Map<String, Set<String>> byResource = new HashMap<>();
            if (meta != null) {
                meta.declaredRelationTargets(conn, predicate).forEach((iri, targets) -> {
                    if (resources.contains(iri)) {
                        byResource.computeIfAbsent(iri, k -> new HashSet<>()).addAll(targets);
                    }
                });
            }
            if (!isAbsoluteUri(predicate)) {
                relations.put(predicate, byResource); // a registered name has no triple form
                continue;
            }
            ParameterizedSparqlString rel = new ParameterizedSparqlString();
            rel.setCommandText("""
                    SELECT DISTINCT ?g ?o WHERE {
                      GRAPH ?g { ?s ?p ?o }
                      FILTER( isIRI(?o) && ( sameTerm(?s, ?g) || STRSTARTS(STR(?s), CONCAT(STR(?g), "#")) ) )
                    }""");
            rel.setIri("p", predicate);
            conn.querySelect(rel.asQuery(), row -> {
                String g = row.getResource("g").getURI();
                if (resources.contains(g)) {
                    byResource.computeIfAbsent(g, k -> new HashSet<>()).add(row.getResource("o").getURI());
                }
            });
            relations.put(predicate, byResource);
        }
        return relations;
    }

    /** The full type set borne by a resource (used by tests and tooling). */
    Set<String> typesOf(String iri) {
        return new LinkedHashSet<>(typeView().getOrDefault(iri, Set.of()));
    }
}
