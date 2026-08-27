package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests the reverse-proxy / TLS posture configuration: the {@code lws.behind-proxy} and
 * {@code lws.require-https} flags, and the HTTPS base-URI validation that backs DPoP/WebID's
 * production TLS assumption.
 *
 * @author Erich Bremer
 */
class LwsConfigurationTest {

    private static LwsConfiguration of(String baseUri, String... extra) {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUri);
        // An owner by default, so these cases exercise the transport and TLS postures rather than
        // tripping the open-mode refusal first. Cases that are about that refusal override it.
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        for (int i = 0; i + 1 < extra.length; i += 2) {
            p.setProperty(extra[i], extra[i + 1]);
        }
        return LwsConfiguration.of(p);
    }

    @Test
    void proxyAndHttpsFlagsDefaultOff() {
        LwsConfiguration c = of("https://storage.example");
        assertFalse(c.behindProxy());
        assertFalse(c.requireHttps());
    }

    @Test
    void parsesProxyAndHttpsFlags() {
        LwsConfiguration c = of("https://storage.example", "lws.behind-proxy", "true", "lws.require-https", "true");
        assertTrue(c.behindProxy());
        assertTrue(c.requireHttps());
    }

    @Test
    void requireHttpsRejectsNonHttpsPublicBaseUri() {
        LwsConfigurationException ex = assertThrows(LwsConfigurationException.class,
                () -> of("http://storage.example", "lws.require-https", "true"));
        assertTrue(ex.getMessage().contains("HTTPS"), ex.getMessage());
    }

    @Test
    void requireHttpsAllowsHttpsAndLoopback() {
        assertNotNull(of("https://storage.example", "lws.require-https", "true"));
        assertNotNull(of("http://localhost:8080", "lws.require-https", "true"));
        assertNotNull(of("http://127.0.0.1:8080", "lws.require-https", "true"));
    }

    @Test
    void plainHttpBaseUriAllowedWhenNotRequired() {
        // Default posture: a non-HTTPS, non-loopback base URI warns but does not fail (dev convenience).
        assertNotNull(of("http://storage.example"));
    }

    @Test
    void tlsDefaultsOffAndDerivesDomainFromBaseUri() {
        LwsConfiguration c = of("https://storage.example");
        assertFalse(c.tlsEnabled());
        assertEquals(List.of("storage.example"), c.acmeDomains());
    }

    @Test
    void tlsRequiresTermsOfServiceAcceptance() {
        LwsConfigurationException ex = assertThrows(LwsConfigurationException.class,
                () -> of("https://storage.example", "lws.tls.enabled", "true"));
        assertTrue(ex.getMessage().contains("accept-terms-of-service"), ex.getMessage());
    }

    @Test
    void tlsEnabledParsesPortsAndDomains() {
        LwsConfiguration c = of("https://storage.example", "lws.tls.enabled", "true",
                "lws.tls.acme.accept-terms-of-service", "true",
                "lws.tls.acme.domains", "a.example b.example");
        assertTrue(c.tlsEnabled());
        assertEquals(443, c.tlsPort());
        assertEquals(80, c.tlsHttpPort());
        assertEquals(List.of("a.example", "b.example"), c.acmeDomains());
    }

    @Test
    void rejectsNonIntegerWithActionableMessage() {
        LwsConfigurationException ex = assertThrows(LwsConfigurationException.class,
                () -> of("https://storage.example", "lws.container.page-size", "lots"));
        assertTrue(ex.getMessage().contains("lws.container.page-size"), ex.getMessage());
        assertTrue(ex.getMessage().contains("lots"), ex.getMessage()); // echoes the offending value
    }

    @Test
    void rejectsOutOfRangePort() {
        LwsConfigurationException ex = assertThrows(LwsConfigurationException.class,
                () -> of("https://storage.example", "lws.tls.port", "70000"));
        assertTrue(ex.getMessage().contains("lws.tls.port"), ex.getMessage());
        assertTrue(ex.getMessage().contains("65535"), ex.getMessage()); // states the valid range
    }

    @Test
    void rejectsUnknownEnumListingAllowedValues() {
        LwsConfigurationException ex = assertThrows(LwsConfigurationException.class,
                () -> of("https://storage.example", "lws.access-control", "rbac"));
        assertTrue(ex.getMessage().contains("OWNER") && ex.getMessage().contains("WAC"), ex.getMessage());
    }

    @Test
    void rejectsNonBooleanValue() {
        LwsConfigurationException ex = assertThrows(LwsConfigurationException.class,
                () -> of("https://storage.example", "lws.public-read", "yes"));
        assertTrue(ex.getMessage().contains("lws.public-read"), ex.getMessage());
    }

    @Test
    void rejectsNonHttpBaseUri() {
        LwsConfigurationException ex = assertThrows(LwsConfigurationException.class, () -> of("ftp://nope.example"));
        assertTrue(ex.getMessage().contains("lws.base-uri"), ex.getMessage());
    }

    // ----- H17: a configuration file that exists but cannot be read -----

    /**
     * Finding H17. Every setting falls back to a development default, so swallowing a read failure
     * turns the <em>hardening</em> step into the vulnerability: an operator does {@code chmod 600}
     * on the file because it holds {@code lws.oidc.client-secret}, the unprivileged service can no
     * longer read it, {@code lws.owners} comes back empty, and open mode makes
     * {@code DefaultAccessPolicy} permit everything.
     */
    @Test
    void refusesToStartWhenTheConfigurationFileCannotBeRead(@TempDir Path dir) throws Exception {
        // A directory where the file should be: unreadable as a file on every platform, unlike
        // chmod, which an administrator would sail past anyway.
        Path unreadable = Files.createDirectory(dir.resolve("lws.properties"));
        Properties p = new Properties();

        LwsConfigurationException e = assertThrows(LwsConfigurationException.class,
                () -> LwsConfiguration.mergeOptionalFile(p, unreadable));
        assertTrue(e.getMessage().contains("Cannot read"), e.getMessage());
    }

    /** A malformed escape is a read failure too, not a reason to fall back to the defaults. */
    @Test
    void refusesToStartOnAMalformedConfigurationFile(@TempDir Path dir) throws Exception {
        // Built without a literal backslash-u in this source: the Java lexer would reject it
        // here before the string ever existed.
        String malformed = "lws.base-uri=http://x" + (char) 92 + "uZZZZ";
        Path file = Files.writeString(dir.resolve("lws.properties"), malformed);
        Properties p = new Properties();

        assertThrows(LwsConfigurationException.class, () -> LwsConfiguration.mergeOptionalFile(p, file));
    }

    /** But an absent file is a supported way to run, and must stay silent. */
    @Test
    void toleratesAnAbsentConfigurationFile(@TempDir Path dir) {
        Properties p = new Properties();
        assertDoesNotThrow(() -> LwsConfiguration.mergeOptionalFile(p, dir.resolve("nothing-here.properties")));
        assertTrue(p.isEmpty());
    }

    /** And a readable one is merged. */
    @Test
    void readsAConfigurationFileThatIsThere(@TempDir Path dir) throws Exception {
        Path file = Files.writeString(dir.resolve("lws.properties"), "lws.owners=https://alice.example/#me");
        Properties p = new Properties();
        LwsConfiguration.mergeOptionalFile(p, file);
        assertEquals("https://alice.example/#me", p.getProperty("lws.owners"));
    }
}
