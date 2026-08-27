package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Tests the SPARQL Update SSRF guard: {@code LOAD}/{@code SERVICE} are rejected unless their host is
 * allow-listed, while local updates and invalid syntax are handled appropriately. The guard only
 * parses and inspects — it never fetches — so these tests touch no network.
 *
 * @author Erich Bremer
 */
class SparqlUpdateGuardTest {

    @Test
    void blocksLoadAndServiceByDefault() {
        assertEquals(403, assertThrows(LwsException.class,
                () -> SparqlUpdateGuard.check("LOAD <http://169.254.169.254/meta>", Set.of())).status());
        assertEquals(403, assertThrows(LwsException.class, () -> SparqlUpdateGuard.check(
                "INSERT { <http://x/> <http://p/> ?o } WHERE { SERVICE <http://evil.example/s> { ?s <http://p/> ?o } }",
                Set.of())).status());
    }

    @Test
    void allowsLocalUpdatesAndAllowlistedHosts() {
        // Local-only updates are always fine.
        SparqlUpdateGuard.check("INSERT DATA { <http://x/> <http://p/> \"v\" }", Set.of());
        SparqlUpdateGuard.check("DELETE WHERE { ?s <http://p/> ?o }", Set.of());

        // LOAD from an allow-listed host is permitted; any other host (or file://) is not.
        SparqlUpdateGuard.check("LOAD <http://trusted.example/g>", Set.of("trusted.example"));
        assertThrows(LwsException.class,
                () -> SparqlUpdateGuard.check("LOAD <http://evil.example/g>", Set.of("trusted.example")));
        assertThrows(LwsException.class,
                () -> SparqlUpdateGuard.check("LOAD <file:///etc/passwd>", Set.of("trusted.example")));
    }

    /**
     * A {@code SERVICE} nested inside a filter expression is the shape that used to slip past the
     * guard: {@code FILTER EXISTS} parses to an {@code ElementFilter} holding an {@code E_Exists},
     * and Jena's element walker does not descend into expressions. The update passed the guard and
     * really did issue the outbound request.
     */
    @Test
    void blocksServiceNestedInsideFilterExpressions() {
        String[] bypasses = {
            "DELETE { ?s ?p ?o } WHERE { ?s ?p ?o FILTER EXISTS { SERVICE <http://evil.example/s> { ?a ?b ?c } } }",
            "DELETE { ?s ?p ?o } WHERE { ?s ?p ?o FILTER NOT EXISTS { SERVICE <http://evil.example/s> { ?a ?b ?c } } }",
            "DELETE { ?s ?p ?o } WHERE { ?s ?p ?o "
                    + "FILTER EXISTS { { SELECT ?a WHERE { SERVICE <http://evil.example/s> { ?a ?b ?c } } } } }",
            // negation and conjunction around the EXISTS: the walk must recurse through operators
            "DELETE { ?s ?p ?o } WHERE { ?s ?p ?o "
                    + "FILTER ( !EXISTS { SERVICE <http://evil.example/s> { ?a ?b ?c } } && true ) }",
            // an expression attached to BIND rather than FILTER
            "DELETE { ?s ?p ?o } WHERE { ?s ?p ?o "
                    + "BIND( EXISTS { SERVICE <http://evil.example/s> { ?a ?b ?c } } AS ?x ) }",
            // inside a sub-select's HAVING
            "DELETE { ?s ?p ?o } WHERE { { SELECT ?s (COUNT(*) AS ?n) WHERE { ?s ?p ?o } GROUP BY ?s "
                    + "HAVING ( EXISTS { SERVICE <http://evil.example/s> { ?a ?b ?c } } ) } ?s ?p ?o }",
        };
        for (String update : bypasses) {
            assertEquals(403, assertThrows(LwsException.class,
                    () -> SparqlUpdateGuard.check(update, Set.of()), update).status(), update);
        }
    }

    /** The same nesting is still permitted when the host is explicitly allow-listed. */
    @Test
    void allowsNestedServiceToAnAllowlistedHost() {
        SparqlUpdateGuard.check(
                "DELETE { ?s ?p ?o } WHERE { ?s ?p ?o "
                        + "FILTER EXISTS { SERVICE <http://trusted.example/s> { ?a ?b ?c } } }",
                Set.of("trusted.example"));
    }

    @Test
    void invalidSyntaxIsBadRequest() {
        assertEquals(400, assertThrows(LwsException.class,
                () -> SparqlUpdateGuard.check("this is not sparql", Set.of())).status());
    }
}
