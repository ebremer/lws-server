package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Properties;
import org.junit.jupiter.api.Test;

/**
 * Batch F, findings M9 / prior-9. The development posture used to be the shipped default and said
 * nothing about itself, so every operator who never read the configuration file was running it: no
 * owners means open mode, where every read, write and control decision is permitted for everybody.
 * It is still available — it now has to be asked for.
 *
 * <p>There is deliberately no {@code lws.profile=production}. A profile that only tightens when it
 * is set is a no-op for exactly the operator it exists to protect.
 *
 * @author Erich Bremer
 */
class FailClosedConfigurationTest {

    private static final String OWNER = "https://alice.example/profile#me";

    /** The one-line statement of the change: the shipped-example minimum is refused. */
    @Test
    void refusesTheDefaultConfigurationBecauseItHasNoOwner() {
        LwsConfigurationException e = assertThrows(LwsConfigurationException.class,
                () -> LwsConfiguration.of(props("lws.base-uri", "https://storage.example")));
        assertTrue(e.getMessage().contains("lws.owners"), e.getMessage());
        assertTrue(e.getMessage().contains("lws.dev.open"), e.getMessage());
    }

    @Test
    void permitsOpenModeWhenItIsAskedFor() {
        LwsConfiguration c = LwsConfiguration.of(props(
                "lws.base-uri", "http://localhost:8080", "lws.dev.open", "true"));
        assertTrue(c.isOpenMode());
        assertTrue(c.devOpen());
    }

    @Test
    void configuredOwnersNeedNoOptIn() {
        LwsConfiguration c = LwsConfiguration.of(props(
                "lws.base-uri", "https://storage.example", "lws.owners", OWNER));
        assertFalse(c.isOpenMode());
        assertFalse(c.devOpen());
    }

    /** WAC is not an escape: its bootstrapped root ACL is what opens the storage in the first place. */
    @Test
    void wacWithNoOwnersIsRefusedToo() {
        LwsConfigurationException e = assertThrows(LwsConfigurationException.class,
                () -> LwsConfiguration.of(props("lws.base-uri", "https://storage.example",
                        "lws.access-control", "wac")));
        assertTrue(e.getMessage().contains("root ACL"), e.getMessage());
    }

    @Test
    void publicReadNowDefaultsToClosed() {
        assertFalse(LwsConfiguration.of(props("lws.base-uri", "https://storage.example",
                "lws.owners", OWNER)).publicReadDefault());
    }

    // ----- developer sign-in -----

    @Test
    void refusesDeveloperSignInOnANonLoopbackBaseUri() {
        assertThrows(LwsConfigurationException.class,
                () -> LwsConfiguration.of(props("lws.base-uri", "https://storage.example",
                        "lws.owners", OWNER, "lws.ui.dev-login", "true")));
    }

    @Test
    void permitsDeveloperSignInOnLoopback() {
        assertDoesNotThrow(() -> LwsConfiguration.of(props("lws.base-uri", "http://localhost:8080",
                "lws.owners", OWNER, "lws.ui.dev-login", "true")));
    }

    /** A development authorization posture and a production transport posture cannot both be true. */
    @Test
    void refusesTheDevelopmentOptInTogetherWithRequireHttps() {
        LwsConfigurationException e = assertThrows(LwsConfigurationException.class,
                () -> LwsConfiguration.of(props("lws.base-uri", "https://storage.example",
                        "lws.dev.open", "true", "lws.require-https", "true")));
        assertTrue(e.getMessage().contains("pick one"), e.getMessage());
    }

    // ----- the loopback test the HTTPS requirement also leans on -----

    /**
     * The old test asked whether the host string started with {@code 127.} or contained
     * {@code ::1}, so a public IPv6 address and an ordinary domain name both counted as loopback —
     * and were therefore exempt from the HTTPS requirement they most needed.
     */
    @Test
    void onlyRealLoopbackAddressesCountAsLoopback() {
        for (String loopback : new String[] {"localhost", "LOCALHOST", "127.0.0.1", "127.1.2.3",
                "::1", "[::1]", "0:0:0:0:0:0:0:1"}) {
            assertTrue(LwsConfiguration.isLoopbackHost(loopback), loopback);
        }
        for (String routable : new String[] {"2001:db8::1", "[2001:db8::1]", "127.example.com",
                "storage.example", "10.0.0.1", "", null}) {
            assertFalse(LwsConfiguration.isLoopbackHost(routable), String.valueOf(routable));
        }
    }

    // ----- the remote metadata store (findings M27, M16) -----

    /**
     * {@code lws.sparql.mode=REMOTE} used to be accepted with all three endpoints blank. The server
     * came up, built an {@code RDFConnectionRemote} with no destination, and died on the first
     * request with a Jena {@code ARQException} naming no configuration key at all.
     */
    @Test
    void remoteBackendRequiresItsEndpoints() {
        Properties p = remote("lws.sparql.remote.accept-no-transactions", "true");
        p.remove("lws.sparql.query");
        LwsConfigurationException e =
                assertThrows(LwsConfigurationException.class, () -> LwsConfiguration.of(p));
        assertTrue(e.getMessage().contains("lws.sparql.query"), e.getMessage());
    }

    @Test
    void remoteEndpointsMustBeAbsoluteHttpUrls() {
        LwsConfigurationException e = assertThrows(LwsConfigurationException.class,
                () -> LwsConfiguration.of(remote("lws.sparql.remote.accept-no-transactions", "true",
                        "lws.sparql.gsp", "file:///tmp/data")));
        assertTrue(e.getMessage().contains("lws.sparql.gsp"), e.getMessage());
    }

    /**
     * Remote SPARQL has no transaction, so a {@code write} callback is a sequence of independent
     * requests: the {@code If-Match} compare-and-swap (H23), ACL erasure committing with the delete
     * (H24) and blob/metadata ordering (H13/H14) all silently stop holding. The mode stays available
     * and now has to be asked for, the same way open mode does.
     */
    @Test
    void remoteBackendMustBeAcknowledged() {
        LwsConfigurationException e = assertThrows(LwsConfigurationException.class,
                () -> LwsConfiguration.of(remote()));
        assertTrue(e.getMessage().contains("lws.sparql.remote.accept-no-transactions"), e.getMessage());
        assertTrue(e.getMessage().contains("compare-and-swap"), e.getMessage());
    }

    @Test
    void remoteBackendIsPermittedWhenAcknowledged() {
        LwsConfiguration c = LwsConfiguration.of(
                remote("lws.sparql.remote.accept-no-transactions", "true"));
        assertEquals(LwsConfiguration.RdfBackend.REMOTE, c.rdfBackend());
        assertTrue(c.sparqlRemoteAcknowledged());
    }

    /** The default backend is unaffected by any of the above. */
    @Test
    void tdb2NeedsNoSparqlEndpoints() {
        assertDoesNotThrow(() -> LwsConfiguration.of(props(
                "lws.base-uri", "https://storage.example", "lws.owners", OWNER)));
    }

    /** A fully specified REMOTE configuration, plus any overrides. */
    private static Properties remote(String... overrides) {
        Properties p = props("lws.base-uri", "https://storage.example", "lws.owners", OWNER,
                "lws.sparql.mode", "REMOTE",
                "lws.sparql.query", "http://localhost:3030/lws/query",
                "lws.sparql.update", "http://localhost:3030/lws/update",
                "lws.sparql.gsp", "http://localhost:3030/lws/data");
        for (int i = 0; i + 1 < overrides.length; i += 2) {
            p.setProperty(overrides[i], overrides[i + 1]);
        }
        return p;
    }

    private static Properties props(String... pairs) {
        Properties p = new Properties();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            p.setProperty(pairs[i], pairs[i + 1]);
        }
        return p;
    }
}
