package com.ebremer.lws.server.core;

import java.net.URI;
import java.util.Set;
import org.apache.jena.graph.Node;
import org.apache.jena.query.Query;
import org.apache.jena.sparql.expr.Expr;
import org.apache.jena.sparql.expr.ExprFunction;
import org.apache.jena.sparql.expr.ExprFunctionOp;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.sparql.modify.request.UpdateBinaryOp;
import org.apache.jena.sparql.modify.request.UpdateCreate;
import org.apache.jena.sparql.modify.request.UpdateData;
import org.apache.jena.sparql.modify.request.UpdateDeleteWhere;
import org.apache.jena.sparql.modify.request.UpdateDropClear;
import org.apache.jena.sparql.modify.request.UpdateLoad;
import org.apache.jena.sparql.modify.request.UpdateModify;
import org.apache.jena.sparql.syntax.ElementAssign;
import org.apache.jena.sparql.syntax.ElementBind;
import org.apache.jena.sparql.syntax.ElementExists;
import org.apache.jena.sparql.syntax.ElementFilter;
import org.apache.jena.sparql.syntax.ElementNamedGraph;
import org.apache.jena.sparql.syntax.ElementNotExists;
import org.apache.jena.sparql.syntax.ElementService;
import org.apache.jena.sparql.syntax.ElementSubQuery;
import org.apache.jena.sparql.syntax.ElementVisitorBase;
import org.apache.jena.sparql.syntax.ElementWalker;
import org.apache.jena.update.Update;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateRequest;

/**
 * Parses a SPARQL Update and guards it in two ways.
 *
 * <p><strong>Server-side request forgery.</strong> The {@code LOAD} operation and any
 * {@code SERVICE} clause — including one nested in a subquery, or inside a {@code FILTER EXISTS} /
 * {@code BIND} expression — cause the server to fetch a URL of the client's choosing. These are
 * rejected unless the target host is explicitly allow-listed (by default the allow-list is empty,
 * so {@code LOAD}/{@code SERVICE} are disabled).
 *
 * <p><strong>Data that would be silently discarded.</strong> An LWS resource is a single RDF graph,
 * and the update is applied to a {@link org.apache.jena.rdf.model.Model}. Jena drops anything an
 * update aims at another graph without raising a thing: {@code INSERT DATA { GRAPH <g> {…} }} was
 * measured leaving the model untouched and the request answered {@code 204} with a new entity-tag,
 * which is finding M38's failure mode on the path finding H21 redirects clients to. Any operation
 * that names a graph — {@code GRAPH}, {@code WITH}, {@code USING}, or graph management such as
 * {@code CREATE}/{@code DROP}/{@code COPY} — is therefore refused rather than quietly ignored.
 *
 * <p>Everything that stays in the resource's own graph — {@code INSERT}/{@code DELETE} (DATA or
 * WHERE) — is unaffected.
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
            requireSingleGraph(operation);
            if (operation instanceof UpdateLoad load) {
                requireAllowed(load.getSource(), allowedHosts);
            }
            if (operation instanceof UpdateModify modify && modify.getWherePattern() != null) {
                ElementWalker.walk(modify.getWherePattern(), new ServiceGuard(allowedHosts));
            }
        }
        return update;
    }

    /**
     * Finds every {@code SERVICE} reachable from a WHERE pattern.
     *
     * <p>Jena's default element walker does not descend into <em>expressions</em>, so visiting only
     * elements misses a {@code SERVICE} nested inside {@code FILTER EXISTS { ... }} — which parses
     * to an {@code ElementFilter} holding an {@code E_Exists}, not to a child element. That shape
     * passed the guard and really did perform the outbound fetch. This visitor therefore walks the
     * expressions attached to {@code FILTER}, {@code BIND} and {@code LET}, and the {@code HAVING}
     * and projection expressions of sub-selects, recursing into the graph pattern that
     * {@code EXISTS}/{@code NOT EXISTS} carries.
     *
     * <p>{@link ExprFunctionOp} is the only expression type that can hold a graph pattern (it is the
     * base of {@code E_Exists} and {@code E_NotExists}), so covering it covers the whole expression
     * surface.
     */
    private static final class ServiceGuard extends ElementVisitorBase {

        private final Set<String> allowedHosts;

        ServiceGuard(Set<String> allowedHosts) {
            this.allowedHosts = allowedHosts;
        }

        @Override
        public void visit(ElementNamedGraph namedGraph) {
            // GRAPH in a WHERE pattern matches nothing here (the update runs against one Model), so
            // the client gets an empty solution set and a silent no-op rather than an answer.
            throw namedGraphRefused("GRAPH " + namedGraph.getGraphNameNode());
        }

        @Override
        public void visit(ElementService service) {
            Node node = service.getServiceNode();
            requireAllowed(node != null && node.isURI() ? node.getURI() : null, allowedHosts);
        }

        @Override
        public void visit(ElementSubQuery subQuery) {
            Query query = subQuery.getQuery();
            if (query == null) {
                return;
            }
            if (query.getQueryPattern() != null) {
                ElementWalker.walk(query.getQueryPattern(), this);
            }
            if (query.getHavingExprs() != null) {
                query.getHavingExprs().forEach(this::walkExpr);
            }
            if (query.getProject() != null) {
                query.getProject().getExprs().values().forEach(this::walkExpr);
            }
        }

        @Override
        public void visit(ElementFilter filter) {
            walkExpr(filter.getExpr());
        }

        @Override
        public void visit(ElementBind bind) {
            walkExpr(bind.getExpr());
        }

        @Override
        public void visit(ElementAssign assign) {
            walkExpr(assign.getExpr());
        }

        // EXISTS also appears as a bare syntax element in some positions; walk it explicitly rather
        // than relying on the default walker to descend.
        @Override
        public void visit(ElementExists exists) {
            if (exists.getElement() != null) {
                ElementWalker.walk(exists.getElement(), this);
            }
        }

        @Override
        public void visit(ElementNotExists notExists) {
            if (notExists.getElement() != null) {
                ElementWalker.walk(notExists.getElement(), this);
            }
        }

        /** Recurse through an expression tree into any graph pattern it carries. */
        private void walkExpr(Expr expr) {
            if (expr == null) {
                return;
            }
            if (expr instanceof ExprFunctionOp op && op.getElement() != null) {
                ElementWalker.walk(op.getElement(), this);
            }
            if (expr instanceof ExprFunction function) {
                for (int i = 1; i <= function.numArgs(); i++) { // Jena's getArg is 1-based
                    walkExpr(function.getArg(i));
                }
            }
        }
    }

    /**
     * Refuse an operation that names a graph other than the resource's own.
     *
     * <p>Not a security control but a truthfulness one: the alternative is not "this is unsafe", it
     * is "this returns 204 and does nothing", which is the failure the whole of Batch H is about.
     */
    private static void requireSingleGraph(Update operation) {
        if (operation instanceof UpdateData data) {
            requireDefaultGraph(data.getQuads());
        } else if (operation instanceof UpdateDeleteWhere delete) {
            requireDefaultGraph(delete.getQuads());
        } else if (operation instanceof UpdateModify modify) {
            if (modify.getWithIRI() != null) {
                throw namedGraphRefused("WITH " + modify.getWithIRI());
            }
            if (!modify.getUsing().isEmpty() || !modify.getUsingNamed().isEmpty()) {
                throw namedGraphRefused("USING");
            }
            requireDefaultGraph(modify.getInsertQuads());
            requireDefaultGraph(modify.getDeleteQuads());
        } else if (operation instanceof UpdateDropClear || operation instanceof UpdateCreate
                || operation instanceof UpdateBinaryOp) {
            // CREATE/DROP/CLEAR/ADD/COPY/MOVE are graph management; there is one graph here to
            // manage and DELETE WHERE already empties it.
            throw namedGraphRefused("graph management (" + operation.getClass().getSimpleName() + ")");
        } else if (operation instanceof UpdateLoad load && load.getDest() != null) {
            throw namedGraphRefused("LOAD INTO GRAPH");
        }
    }

    private static void requireDefaultGraph(Iterable<Quad> quads) {
        for (Quad quad : quads) {
            if (!quad.isDefaultGraph()) {
                throw namedGraphRefused("GRAPH " + quad.getGraph());
            }
        }
    }

    private static LwsException namedGraphRefused(String what) {
        return LwsException.badRequest(
                "This resource is a single RDF graph, so an update that names another cannot be "
                        + "applied: " + what);
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
