package com.ebremer.lws.server.core;

import java.net.URI;
import java.util.Set;
import org.apache.jena.graph.Node;
import org.apache.jena.sparql.modify.request.UpdateLoad;
import org.apache.jena.sparql.modify.request.UpdateModify;
import org.apache.jena.sparql.syntax.ElementService;
import org.apache.jena.sparql.syntax.ElementSubQuery;
import org.apache.jena.sparql.syntax.ElementVisitorBase;
import org.apache.jena.sparql.syntax.ElementWalker;
import org.apache.jena.update.Update;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateRequest;

/**
 * Parses a SPARQL Update and guards against server-side request forgery: the {@code LOAD} operation
 * and any {@code SERVICE} clause (including in subqueries) cause the server to fetch a URL of the
 * client's choosing. These are rejected unless the target host is explicitly allow-listed
 * (by default the allow-list is empty, so {@code LOAD}/{@code SERVICE} are disabled). All other
 * update operations — {@code INSERT}/{@code DELETE} (DATA or WHERE), {@code CLEAR}, etc. — operate
 * only on the local graph and are unaffected.
 *
 * @author Erich Bremer
 */
public final class SparqlUpdateGuard {

    private SparqlUpdateGuard() {
    }

    /**
     * Parse {@code sparql} and verify it contains no disallowed external fetch.
     *
     * @return the parsed request (so the caller need not re-parse)
     * @throws LwsException 400 if the update is syntactically invalid, 403 if it would fetch a
     *         non-allow-listed host
     */
    public static UpdateRequest check(String sparql, Set<String> allowedHosts) {
        UpdateRequest update;
        try {
            update = UpdateFactory.create(sparql);
        } catch (RuntimeException e) {
            throw LwsException.badRequest("Invalid SPARQL Update: " + e.getMessage());
        }
        for (Update operation : update.getOperations()) {
            if (operation instanceof UpdateLoad load) {
                requireAllowed(load.getSource(), allowedHosts);
            }
            if (operation instanceof UpdateModify modify && modify.getWherePattern() != null) {
                ElementWalker.walk(modify.getWherePattern(), new ElementVisitorBase() {
                    @Override
                    public void visit(ElementService service) {
                        Node node = service.getServiceNode();
                        requireAllowed(node != null && node.isURI() ? node.getURI() : null, allowedHosts);
                    }

                    @Override
                    public void visit(ElementSubQuery subQuery) {
                        if (subQuery.getQuery() != null && subQuery.getQuery().getQueryPattern() != null) {
                            ElementWalker.walk(subQuery.getQuery().getQueryPattern(), this);
                        }
                    }
                });
            }
        }
        return update;
    }

    private static void requireAllowed(String iri, Set<String> allowedHosts) {
        String host = hostOf(iri);
        if (host == null || !allowedHosts.contains(host.toLowerCase())) {
            throw LwsException.forbidden(
                    "SPARQL Update may not fetch <" + iri + ">: LOAD/SERVICE to that host is not permitted");
        }
    }

    private static String hostOf(String iri) {
        if (iri == null) {
            return null;
        }
        try {
            return new URI(iri).getHost();
        } catch (Exception e) {
            return null;
        }
    }
}
