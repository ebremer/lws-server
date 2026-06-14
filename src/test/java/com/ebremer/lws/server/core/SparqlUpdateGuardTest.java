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

    @Test
    void invalidSyntaxIsBadRequest() {
        assertEquals(400, assertThrows(LwsException.class,
                () -> SparqlUpdateGuard.check("this is not sparql", Set.of())).status());
    }
}
