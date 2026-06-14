package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;

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
}
