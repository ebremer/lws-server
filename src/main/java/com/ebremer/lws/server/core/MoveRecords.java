package com.ebremer.lws.server.core;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.rdfconnection.RDFConnection;

/**
 * Where moved resources went: one record per move, from the IRI the moved resource had to the one it
 * has now, so that a request for a previous identifier can be answered {@code 301 Moved Permanently}
 * (lws10-core, Moving Resources: a server that does not preserve identifiers "SHOULD respond to
 * subsequent requests on the previous identifiers of the resource and of its auxiliary resources with
 * 301 Moved Permanently, including a Location header field pointing at the new identifier").
 *
 * <p><b>A graph of its own</b>, not the registry's administrative graph. The registry's
 * {@code exists} is "any triple with this subject", so a record keyed by a previous IRI in that graph
 * would make the previous IRI exist — as a resource with no type, no parent and no content. Kept
 * apart, a record is only ever consulted by {@link #lookup}, and only when nothing is stored at the
 * IRI asked for: a resource created at a previous IRI simply takes precedence.
 *
 * <p><b>A moved container is one record</b>, covering its descendants and their auxiliary resources
 * by prefix: {@code /a/ -> /b/a/} answers {@code /a/x} with {@code /b/a/x}. The record of the
 * resource itself wins over a container's, and a deeper container's over a shallower one's, so a
 * resource moved out of a container before the container itself moved is still found where it went.
 * A container's record covers only what is no longer there: once something is stored at the
 * container's previous IRI again, the paths under it belong to that, and the record stops there.
 *
 * <p><b>Records point at where the resource is now.</b> Moving a resource again rewrites the records
 * that led to its previous IRI, so a previous identifier answers with the current one rather than
 * with a chain of hops through IRIs that may since have been reused; a record that would now lead
 * to itself, and the record of the IRI the resource now occupies, are dropped. Deleting a resource
 * drops the records that lead to it, and the record of the IRI it occupied.
 *
 * <p>All methods take the caller's connection, so a record is written in the transaction of the move
 * it records and can neither outlive a move that rolls back nor be missing from one that commits.
 *
 * @author Erich Bremer
 */
final class MoveRecords {

    /** The named graph holding one {@code <previous> <movedTo> <current>} triple per move. */
    static final String GRAPH = "urn:x-lws:moved";
    private static final String MOVED_TO = "urn:x-lws:movedTo";

    private MoveRecords() {
    }

    /**
     * Record that the resource at {@code from} is now at {@code to}, keeping every other record
     * pointing at where its resource is now. A container's IRIs end in {@code /}, so the prefix
     * tests below cover its descendants and nothing else.
     */
    static void record(RDFConnection conn, String from, String to) {
        // Records that led to `from`, or into it, now lead to `to` — except one that would now lead
        // to itself, which is what a move back to where a resource came from makes of its record.
        for (String[] row : select(conn, "?t", from, from.endsWith("/"))) {
            delete(conn, row[0], row[1]);
            String now = to + row[1].substring(from.length());
            if (!now.equals(row[0])) {
                insert(conn, row[0], now);
            }
        }
        // The record of `to` itself is about an IRI the moved resource now occupies, which takes
        // precedence over it; were the resource deleted there later, the record must not revive.
        for (String[] row : select(conn, "?s", to, false)) {
            delete(conn, row[0], row[1]);
        }
        insert(conn, from, to);
    }

    /**
     * Where a request for {@code iri}, at which nothing is stored, should be sent, or {@code null} if
     * no record applies: the record of {@code iri} itself, else that of its nearest moved ancestor
     * container, with the remainder of the path carried over. The search stops at the nearest
     * ancestor that is {@code occupied}: whatever is stored there is the container the path is
     * under now, whatever moved away from that IRI before. Says nothing about whether what a record
     * leads to exists, or about who may know; the caller decides both.
     */
    static String lookup(RDFConnection conn, String baseUri, String iri, Predicate<String> occupied) {
        for (String candidate : candidates(baseUri, iri)) {
            if (!candidate.equals(iri) && occupied.test(candidate)) {
                return null;
            }
            String to = target(conn, candidate);
            if (to != null) {
                return to + iri.substring(candidate.length());
            }
        }
        return null;
    }

    /** Drop every record leading to {@code iri}, and the record of {@code iri} itself. */
    static void forget(RDFConnection conn, String iri) {
        ParameterizedSparqlString u = new ParameterizedSparqlString();
        u.setCommandText("DELETE { GRAPH ?g { ?s ?p ?t } } "
                + "WHERE { GRAPH ?g { ?s ?p ?t } FILTER( ?s = ?iri || ?t = ?iri ) }");
        u.setIri("g", GRAPH);
        u.setIri("p", MOVED_TO);
        u.setIri("iri", iri);
        conn.update(u.asUpdate());
    }

    /**
     * {@code iri}, then each container above it, nearest first; the storage root is left out, as it
     * cannot move. Empty for an IRI outside this storage.
     */
    private static List<String> candidates(String baseUri, String iri) {
        List<String> out = new ArrayList<>();
        String path = Iris.toPath(baseUri, iri);
        if (path == null) {
            return out;
        }
        out.add(iri);
        for (String parent = Iris.parentPath(path); parent != null && !Iris.isRoot(parent);
                parent = Iris.parentPath(parent)) {
            out.add(Iris.toIri(baseUri, parent));
        }
        return out;
    }

    private static String target(RDFConnection conn, String from) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("SELECT ?t WHERE { GRAPH ?g { ?s ?p ?t } } LIMIT 1");
        q.setIri("g", GRAPH);
        q.setIri("s", from);
        q.setIri("p", MOVED_TO);
        String[] holder = new String[1];
        conn.querySelect(q.asQuery(), row -> holder[0] = row.getResource("t").getURI());
        return holder[0];
    }

    /**
     * The records whose {@code position} — {@code ?s}, the previous IRI, or {@code ?t}, the current
     * one — is {@code iri} or, for a container, lies under it; as {@code [previous, current]} pairs.
     */
    private static List<String[]> select(RDFConnection conn, String position, String iri, boolean container) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("SELECT ?s ?t WHERE { GRAPH ?g { ?s ?p ?t } FILTER( " + position + " = ?key"
                + (container ? " || STRSTARTS(STR(" + position + "), STR(?key))" : "") + " ) }");
        q.setIri("g", GRAPH);
        q.setIri("p", MOVED_TO);
        q.setIri("key", iri);
        List<String[]> out = new ArrayList<>();
        conn.querySelect(q.asQuery(), row ->
                out.add(new String[] {row.getResource("s").getURI(), row.getResource("t").getURI()}));
        return out;
    }

    private static void insert(RDFConnection conn, String from, String to) {
        ParameterizedSparqlString u = new ParameterizedSparqlString();
        u.setCommandText("INSERT DATA { GRAPH ?g { ?s ?p ?t } }");
        u.setIri("g", GRAPH);
        u.setIri("s", from);
        u.setIri("p", MOVED_TO);
        u.setIri("t", to);
        conn.update(u.asUpdate());
    }

    private static void delete(RDFConnection conn, String from, String to) {
        ParameterizedSparqlString u = new ParameterizedSparqlString();
        u.setCommandText("DELETE DATA { GRAPH ?g { ?s ?p ?t } }");
        u.setIri("g", GRAPH);
        u.setIri("s", from);
        u.setIri("p", MOVED_TO);
        u.setIri("t", to);
        conn.update(u.asUpdate());
    }
}
