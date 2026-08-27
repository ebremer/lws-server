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

    /**
     * The ranges the JDK's own predicates do not know about. {@code isSiteLocalAddress} covers only
     * RFC 1918, so carrier-grade NAT — where a great many hosts' actual neighbours live — walked
     * straight through, as did the IETF protocol range that carries NAT64 and DS-Lite.
     */
    @Test
    void blocksTheReservedRangesTheJdkPredicatesMiss() {
        assertFalse(strict.permits("http://100.64.0.1/x"), "carrier-grade NAT");
        assertFalse(strict.permits("http://100.127.255.254/x"), "carrier-grade NAT, top of range");
        assertTrue(strict.permits("http://100.63.255.255/x"), "just below carrier-grade NAT");
        assertTrue(strict.permits("http://100.128.0.1/x"), "just above carrier-grade NAT");
        assertFalse(strict.permits("http://198.18.0.1/x"), "benchmarking");
        assertFalse(strict.permits("http://192.0.0.1/x"), "IETF protocol assignments");
        assertFalse(strict.permits("http://192.0.2.1/x"), "TEST-NET-1");
        assertFalse(strict.permits("http://203.0.113.9/x"), "TEST-NET-3");
        assertFalse(strict.permits("http://240.0.0.1/x"), "reserved");
    }

    /**
     * The same host reached by a name none of the IPv6 predicates recognise. Without this,
     * {@code [::ffff:169.254.169.254]} walks past a guard whose whole purpose is to refuse
     * {@code 169.254.169.254}.
     */
    @Test
    void blocksAnIpv4AddressTunnelledInsideAnIpv6One() {
        assertFalse(strict.permits("http://[::ffff:169.254.169.254]/latest/meta-data/"), "IPv4-mapped");
        assertFalse(strict.permits("http://[::ffff:10.0.0.5]/x"), "IPv4-mapped, RFC 1918");
        assertFalse(strict.permits("http://[::a9fe:a9fe]/x"), "IPv4-compatible");
        assertFalse(strict.permits("http://[2002:a9fe:a9fe::1]/x"), "6to4 wrapping 169.254.169.254");
        assertFalse(strict.permits("http://[2002:0a00:0005::1]/x"), "6to4 wrapping 10.0.0.5");
        assertFalse(strict.permits("http://[64:ff9b::a9fe:a9fe]/x"), "NAT64 well-known prefix");
        // ...and a 6to4 address wrapping a genuinely public IPv4 address is still permitted, so the
        // rule is "check what it tunnels", not "refuse the whole form".
        assertTrue(strict.permits("http://[2002:0808:0808::1]/x"), "6to4 wrapping 8.8.8.8");
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
