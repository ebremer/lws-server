package com.ebremer.lws.server.auth;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdfconnection.RDFConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.Iris;
import com.ebremer.lws.server.core.LwsResource;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceType;
import com.ebremer.lws.server.rdf.RdfStore;

/**
 * Moves Web Access Control ACLs written by an earlier build out of the client-reachable IRI space,
 * and reports what it finds.
 *
 * <p>ACLs used to be stored in a named graph called {@code <resource>.acl} — an ordinary resource
 * IRI. Resource content is stored in a graph named by the resource's own IRI, so creating a resource
 * at that address overwrote the ACL governing its target (finding C2). ACLs now live in
 * {@link WacAclService#ACL_GRAPH_PREFIX}, so nothing reads the old names any more; an existing store
 * still holds them, and a legitimate one must be carried forward or the operator's access control
 * silently evaporates on upgrade.
 *
 * <p><b>Two populations share those names, and they are treated oppositely.</b> The discriminator is
 * whether the graph name is also a resource-registry subject. {@link WacAclService#putAclFor} is the
 * only writer in the server that creates a named graph without a registry entry; every other graph
 * write — {@code ResourceService.storeContent}, both patch paths, delete — pairs the graph and the
 * registry entry in one transaction, and no request-reachable operation removes a registry entry
 * while leaving its graph. So a graph with no entry was written by the old ACL code, and a graph
 * with one was created through the resource API — which is to say, possibly by the very attack this
 * change closes. The first is migrated; the second is never promoted.
 *
 * <p>Deliberately <em>not</em> based on the graph's contents. An attacker writes
 * {@code acl:Authorization} triples too — they are the payload.
 *
 * @author Erich Bremer
 */
public final class LegacyAclMigration {

    private static final Logger log = LoggerFactory.getLogger(LegacyAclMigration.class);

    private LegacyAclMigration() {
    }

    /**
     * Carry legitimate legacy ACLs forward, quarantine graphs that are really resources, and drop
     * ACLs whose target no longer exists. Idempotent: a second run finds nothing to do.
     *
     * <p>Run before the root ACL is bootstrapped. That ordering is what makes an already-exploited
     * store recover by itself: a planted {@code /.acl} is a registered resource, so it is
     * quarantined rather than promoted, which leaves the root with no ACL — and bootstrapping then
     * rebuilds it from {@code lws.owners}, restoring the owner the attack locked out.
     */
    public static void migrate(RdfStore rdf, LwsConfiguration config, ResourceRegistry registry) {
        rdf.writeDo(conn -> {
            for (String graph : legacyAclGraphs(conn, config)) {
                String targetIri = targetOf(graph);
                Optional<LwsResource> entry = registry.find(conn, graph);
                if (entry.isPresent() && ownsItsOwnGraph(entry.get())) {
                    log.warn("Not promoting {} to an ACL for {}: it is a registered RDF resource, so "
                            + "this graph is its content, not an ACL this server wrote. It has no "
                            + "effect on authorization.", graph, targetIri);
                    continue;
                }
                if (entry.isPresent()) {
                    // A binary resource keeps its bytes in the blob store and a container has no
                    // graph at all, so neither could have written what is at this name — the graph
                    // is the server's own ACL, sitting underneath a resource that merely occupies
                    // the address. Migrate the ACL; the resource itself is left alone, unreachable
                    // and now uncreatable.
                    log.warn("A registered resource occupies the ACL address {}, but the graph there "
                            + "is an ACL for {} and is being migrated.", graph, targetIri);
                }
                String destination = WacAclService.aclGraphName(targetIri);
                Model legacy = WacAclService.fetchOrEmpty(conn, graph);
                Model existing = WacAclService.fetchOrEmpty(conn, destination);
                if (!existing.isEmpty() && !existing.isIsomorphicWith(legacy)) {
                    log.warn("Leaving legacy ACL {} in place: {} already holds a different ACL. "
                            + "Reconcile them by hand.", graph, destination);
                    continue;
                }
                // Copy before delete. On TDB2 the whole loop is one transaction so the order is
                // invisible, but a remote SPARQL backend autocommits each operation, and an
                // interruption must leave the ACL readable at one name or both — never at neither,
                // which would silently hand the resource to whatever an ancestor's acl:default says.
                conn.put(destination, legacy);
                conn.delete(graph);
                // A migrated ACL is a version like any other and needs the entity-tag that names it
                // (prior-review finding 13). Without one, GET emits no ETag and PUT demands no
                // precondition — so a storage whose ACLs came through this path would have kept the
                // pre-fix, unconditional behaviour for exactly the ACLs an operator inherited.
                WacAclService.writeSystemAclEtag(conn, targetIri);
                log.warn("Migrated legacy ACL {} to {}", graph, destination);
            }
            for (String orphan : orphanedAclGraphs(conn, registry)) {
                conn.delete(orphan);
                // And its tag with it, in the same unit of work — a tag outliving the graph it
                // describes is the H24 resurrection one indirection over: a resource created at that
                // path later would be handed the version identifier of an ACL that no longer exists.
                WacAclService.deleteSystemAclEtag(conn,
                        orphan.substring(WacAclService.ACL_GRAPH_PREFIX.length()));
                log.warn("Removed the ACL {}: its target no longer exists", orphan);
            }
        });
    }

    /**
     * Report, changing nothing, what {@link #migrate} would do. Used in owner mode, where no ACL is
     * read at all: the operator sees which legacy ACLs would come alive, and which {@code *.acl}
     * resources would be refused, <em>before</em> switching {@code lws.access-control} to {@code wac}.
     */
    public static void report(RdfStore rdf, LwsConfiguration config, ResourceRegistry registry) {
        rdf.readDo(conn -> {
            for (String graph : legacyAclGraphs(conn, config)) {
                if (registry.find(conn, graph).filter(LegacyAclMigration::ownsItsOwnGraph).isPresent()) {
                    log.warn("Web Access Control is off, but a resource occupies the ACL address {}. "
                            + "If access-control is switched to WAC it will be refused, not honoured.", graph);
                } else {
                    log.warn("Web Access Control is off, but {} holds an ACL from an earlier version. "
                            + "If access-control is switched to WAC it will govern {}.",
                            graph, targetOf(graph));
                }
            }
        });
    }

    /**
     * Every non-empty graph named like a resource in this storage and ending in {@code .acl}.
     *
     * <p>Expressed in SPARQL rather than {@code Dataset.listNames()} because the store may be a
     * remote SPARQL service, where only this form works; and with bound literals rather than
     * concatenation because the values being matched are graph names out of the store.
     */
    private static List<String> legacyAclGraphs(RDFConnection conn, LwsConfiguration config) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } "
                + "FILTER( STRSTARTS(STR(?g), ?prefix) && STRENDS(STR(?g), ?suffix) ) } ORDER BY ?g");
        q.setLiteral("prefix", config.baseUri() + "/");
        q.setLiteral("suffix", Iris.ACL_SUFFIX);
        List<String> names = new ArrayList<>();
        conn.querySelect(q.asQuery(), row -> names.add(row.getResource("g").getURI()));
        return names;
    }

    /**
     * ACL graphs whose target has no registry entry. Nothing reachable over HTTP creates one — an
     * ACL {@code PUT} requires its target to exist — so these are strays: left behind when a delete
     * failed halfway, or when a resource was deleted while the server was running in owner mode,
     * where the listener that drops a resource's ACL is not even registered. Left in place they
     * would govern whatever is created at that path next.
     */
    private static List<String> orphanedAclGraphs(RDFConnection conn, ResourceRegistry registry) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } "
                + "FILTER( STRSTARTS(STR(?g), ?prefix) ) } ORDER BY ?g");
        q.setLiteral("prefix", WacAclService.ACL_GRAPH_PREFIX);
        List<String> names = new ArrayList<>();
        conn.querySelect(q.asQuery(), row -> names.add(row.getResource("g").getURI()));
        return names.stream()
                .filter(g -> !registry.exists(conn, g.substring(WacAclService.ACL_GRAPH_PREFIX.length())))
                .toList();
    }

    /**
     * True if this registry entry is the kind that stores its content in a named graph at its own
     * IRI — that is, an RDF source.
     *
     * <p>The distinction decides whether a graph at an ACL address is the server's ACL or a
     * client's content, so getting it wrong is not cosmetic in either direction. A container has no
     * graph, and a binary resource's bytes live in the blob store, so an entry of either kind can
     * sit at {@code /c/.acl} while the graph at that name is still the ACL for {@code /c/} —
     * quarantining <em>that</em> would silently drop a live ACL and drop the resource back to
     * whatever an ancestor's {@code acl:default} allows. The byte-size and key tests are belt and
     * braces: {@code ResourceRegistry} infers "binary" from {@code lws:binaryKey} alone, so a row
     * written without one would otherwise read back as an RDF source.
     */
    private static boolean ownsItsOwnGraph(LwsResource entry) {
        return entry.type() == ResourceType.RDF_SOURCE && entry.binaryKey() == null && entry.size() < 0;
    }

    /** {@code <base>/c/.acl} -> {@code <base>/c/}; {@code <base>/x.acl} -> {@code <base>/x}. */
    private static String targetOf(String legacyGraphName) {
        return legacyGraphName.substring(0, legacyGraphName.length() - Iris.ACL_SUFFIX.length());
    }
}
