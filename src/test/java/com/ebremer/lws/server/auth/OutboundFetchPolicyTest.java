package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Tests the outbound-fetch SSRF guard. Uses IP literals and {@code localhost} (resolved locally) so
 * the assertions are deterministic and make no external DNS or network calls.
 *
 * @author Erich Bremer
 */
class OutboundFetchPolicyTest {

    private final OutboundFetchPolicy strict = new OutboundFetchPolicy(true, Set.of());

    @Test
    void permitsPublicHttpHost() {
        assertTrue(strict.permits("https://8.8.8.8/.well-known/openid-configuration"));
    }

    @Test
    void blocksNonHttpSchemes() {
        assertFalse(strict.permits("file:///etc/passwd"));        // local-file read via Jena loader
        assertFalse(strict.permits("ftp://8.8.8.8/x"));
        assertFalse(strict.permits("jar:file:///x!/y"));
        // The scheme block applies even when the private-address block is off.
        assertFalse(OutboundFetchPolicy.permitAll().permits("file:///etc/passwd"));
    }

    @Test
    void blocksLoopbackPrivateAndMetadataAddresses() {
        assertFalse(strict.permits("http://127.0.0.1/x"));
        assertFalse(strict.permits("http://localhost/x"));
        assertFalse(strict.permits("http://169.254.169.254/latest/meta-data/")); // cloud metadata
        assertFalse(strict.permits("http://10.0.0.5/x"));
        assertFalse(strict.permits("http://192.168.1.1/x"));
        assertFalse(strict.permits("http://0.0.0.0/x"));
    }

    @Test
    void allowListExemptsAHost() {
        OutboundFetchPolicy exempt = new OutboundFetchPolicy(true, Set.of("idp.internal", "127.0.0.1"));
        assertTrue(exempt.permits("http://127.0.0.1/x"), "an allow-listed host bypasses the address block");
    }

    @Test
    void privateBlockCanBeDisabled() {
        OutboundFetchPolicy open = new OutboundFetchPolicy(false, Set.of());
        assertTrue(open.permits("http://10.0.0.5/x"));
        assertTrue(open.permits("http://localhost/x"));
        assertFalse(open.permits("file:///x"), "the scheme restriction still applies");
    }
}
