package com.ebremer.lws.server.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.EnumSet;
import java.util.Properties;
import jakarta.servlet.DispatcherType;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.util.KeyPairUtils;
import com.ebremer.lws.server.TestDirs;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Tests the TLS/ACME support that does not require a live CA: the HTTP-01 challenge servlet and the
 * HTTP&rarr;HTTPS redirect filter (over a live HTTP connector), and assembling a Jetty keystore from
 * a persisted domain key and certificate chain. The live ACME ordering flow needs a publicly
 * reachable domain and is exercised only by compilation.
 *
 * @author Erich Bremer
 */
class AcmeSupportTest {

    /**
     * A fresh data directory per test. Deleted on the way out where the platform allows it, and by
     * the next run's sweep where it does not — see {@link TestDirs}.
     */
    private final Path tempDir = TestDirs.create();

    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @Test
    void challengeIsServedOverHttpAndOtherPathsRedirectToHttps() throws Exception {
        AcmeChallengeStore store = new AcmeChallengeStore();
        store.put("tok", "tok.keyAuth");

        Server server = new Server();
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(0);
        server.addConnector(connector);
        ServletContextHandler ctx = new ServletContextHandler();
        ctx.setContextPath("/");
        ctx.addFilter(new FilterHolder(new HttpsRedirectFilter(8443, "https://localhost:8443", () -> true)),
                "/*", EnumSet.of(DispatcherType.REQUEST));
        ctx.addServlet(new ServletHolder(new AcmeChallengeServlet(store)), AcmeChallengeServlet.PATH + "*");
        server.setHandler(ctx);
        server.start();
        try {
            int port = connector.getLocalPort();
            // The HTTP-01 challenge is served over plaintext HTTP and is NOT redirected.
            HttpResponse<String> ok = get(port, AcmeChallengeServlet.PATH + "tok");
            assertEquals(200, ok.statusCode());
            assertEquals("tok.keyAuth", ok.body());
            // An unknown token is 404.
            assertEquals(404, get(port, AcmeChallengeServlet.PATH + "missing").statusCode());
            // Any other plaintext path is redirected to HTTPS with 308, which preserves the method
            // and body — a 301 lets a client rewrite POST to GET, silently turning a redirected
            // write into a read.
            HttpResponse<String> redirect = get(port, "/some/resource");
            assertEquals(308, redirect.statusCode());
            assertEquals("https://localhost:8443/some/resource",
                    redirect.headers().firstValue("Location").orElse(""));
            // Deliberately NO Strict-Transport-Security here. RFC 6797 section 8.1 requires a user
            // agent to ignore an STS header received over a non-secure transport, so setting it on
            // this plaintext redirect advertised HSTS that no browser ever recorded. It lives in
            // HstsFilter now, on the secure responses where it takes effect (finding M28).
            assertTrue(redirect.headers().firstValue("Strict-Transport-Security").isEmpty(),
                    "HSTS over plaintext is ignored by every user agent; it belongs on the TLS response");

            // The redirect target comes from the configured base URI, not from the Host header —
            // reflecting Host made this an open redirect any client could aim anywhere. Sent over a
            // raw socket because the JDK HttpClient refuses to let a caller set Host.
            String spoofed = rawGet(port, "/some/resource", "evil.example");
            assertTrue(spoofed.contains("Location: https://localhost:8443/some/resource"),
                    "a lying Host header must not choose the redirect target: " + spoofed);
            assertFalse(spoofed.contains("evil.example"), spoofed);
        } finally {
            server.stop();
        }
    }

    /**
     * Until the HTTPS connector is up there is nowhere to redirect to, so the answer is a
     * non-cacheable {@code 503} rather than a <em>permanent</em> redirect to a dead port.
     *
     * <p>Against the pre-fix code every one of these is a {@code 308} — the filter went live with
     * {@code server.start()} while {@code enableTls} was still blocking on the whole ACME order, and
     * browsers and intermediaries cache a {@code 308} indefinitely, so a client that arrived during
     * provisioning could keep being sent to a closed port long after TLS came up (finding M28).
     */
    @Test
    void plaintextIsRefusedRatherThanRedirectedWhileHttpsIsStillComingUp() throws Exception {
        AcmeChallengeStore store = new AcmeChallengeStore();
        store.put("tok", "tok.keyAuth");
        java.util.concurrent.atomic.AtomicBoolean ready = new java.util.concurrent.atomic.AtomicBoolean();

        Server server = new Server();
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(0);
        server.addConnector(connector);
        ServletContextHandler ctx = new ServletContextHandler();
        ctx.setContextPath("/");
        ctx.addFilter(new FilterHolder(new HttpsRedirectFilter(8443, "https://localhost:8443", ready::get)),
                "/*", EnumSet.of(DispatcherType.REQUEST));
        ctx.addServlet(new ServletHolder(new AcmeChallengeServlet(store)), AcmeChallengeServlet.PATH + "*");
        server.setHandler(ctx);
        server.start();
        try {
            int port = connector.getLocalPort();
            HttpResponse<String> tooEarly = get(port, "/some/resource");
            assertEquals(503, tooEarly.statusCode(), "no redirect before there is anywhere to go");
            assertTrue(tooEarly.headers().firstValue("Retry-After").isPresent(), "503 says when to come back");
            assertTrue(tooEarly.headers().firstValue("Location").isEmpty(), "and names no destination");

            // The console is included, deliberately: it runs on a session cookie, and serving it in
            // the clear on a server configured to terminate TLS is the downgrade this prevents.
            assertEquals(503, get(port, "/app/browse").statusCode());

            // The ACME challenge is exempt, because it is how the outage ends.
            assertEquals(200, get(port, AcmeChallengeServlet.PATH + "tok").statusCode());

            ready.set(true);
            assertEquals(308, get(port, "/some/resource").statusCode(), "redirecting once TLS is up");
        } finally {
            server.stop();
        }
    }

    /** HSTS goes on the responses that were actually served over TLS, and only there. */
    @Test
    void hstsIsEmittedOnSecureResponsesOnly() throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "https://storage.example");
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        HstsFilter filter = HstsFilter.forConfig(LwsConfiguration.of(p));
        assertNotNull(filter, "an https base URI gets the filter");

        assertEquals("max-age=31536000", headerFrom(filter, true));
        assertNull(headerFrom(filter, false), "a plaintext response gets none: RFC 6797 §8.1");

        // A plaintext storage must not tell browsers to use HTTPS for its host — it would make the
        // storage unreachable — and max-age=0 is an explicit opt-out.
        Properties plain = new Properties();
        plain.setProperty("lws.base-uri", "http://localhost:8080");
        plain.setProperty("lws.dev.open", "true");
        assertNull(HstsFilter.forConfig(LwsConfiguration.of(plain)));
        Properties off = new Properties();
        off.setProperty("lws.base-uri", "https://storage.example");
        off.setProperty("lws.owners", "https://owner.example/profile#me");
        off.setProperty("lws.hsts.max-age-seconds", "0");
        assertNull(HstsFilter.forConfig(LwsConfiguration.of(off)));
    }

    /** Run the filter over a stub request/response pair and return the STS header it set, if any. */
    private static String headerFrom(HstsFilter filter, boolean secure) throws Exception {
        java.util.Map<String, String> set = new java.util.HashMap<>();
        jakarta.servlet.http.HttpServletRequest request =
                (jakarta.servlet.http.HttpServletRequest) java.lang.reflect.Proxy.newProxyInstance(
                        AcmeSupportTest.class.getClassLoader(),
                        new Class<?>[] {jakarta.servlet.http.HttpServletRequest.class},
                        (proxy, method, args) -> "isSecure".equals(method.getName()) ? secure
                                : defaultFor(method.getReturnType()));
        jakarta.servlet.http.HttpServletResponse response =
                (jakarta.servlet.http.HttpServletResponse) java.lang.reflect.Proxy.newProxyInstance(
                        AcmeSupportTest.class.getClassLoader(),
                        new Class<?>[] {jakarta.servlet.http.HttpServletResponse.class},
                        (proxy, method, args) -> {
                            if ("setHeader".equals(method.getName())) {
                                set.put((String) args[0], (String) args[1]);
                            }
                            return defaultFor(method.getReturnType());
                        });
        filter.doFilter(request, response, (rq, rs) -> { });
        return set.get("Strict-Transport-Security");
    }

    private static Object defaultFor(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        return type == boolean.class ? Boolean.FALSE : type == int.class ? Integer.valueOf(0) : Long.valueOf(0);
    }

    @Test
    void buildsKeyStoreFromDomainKeyAndCertificateChain() throws Exception {
        Path dir = tempDir;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "https://example.com");
        // An owner, because this class asserts nothing about authorization and the
        // development posture now has to be asked for explicitly.
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        p.setProperty("lws.tls.enabled", "true");
        p.setProperty("lws.tls.acme.accept-terms-of-service", "true");
        p.setProperty("lws.tls.dir", dir.toString());
        LwsConfiguration config = LwsConfiguration.of(p);

        KeyPair domainKey = KeyPairUtils.createKeyPair(2048);
        try (var w = Files.newBufferedWriter(dir.resolve("domain.key"))) {
            KeyPairUtils.writeKeyPair(domainKey, w);
        }
        Files.writeString(dir.resolve("domain-chain.crt"), pem(selfSigned(domainKey)));

        AcmeCertificateManager manager = new AcmeCertificateManager(config, new AcmeChallengeStore());
        KeyStore keyStore = manager.buildKeyStore();
        assertTrue(keyStore.containsAlias("lws"));
        assertNotNull(keyStore.getKey("lws", manager.keystorePassword()), "private key entry present");
        assertEquals(1, keyStore.getCertificateChain("lws").length);
    }

    /** A single plaintext GET with an attacker-chosen Host, returning the raw response head. */
    private static String rawGet(int port, String path, String host) throws Exception {
        String crlf = "" + (char) 13 + (char) 10;
        String request = "GET " + path + " HTTP/1.1" + crlf
                + "Host: " + host + crlf
                + "Connection: close" + crlf + crlf;
        try (java.net.Socket socket = new java.net.Socket("localhost", port)) {
            socket.getOutputStream().write(request.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            socket.getOutputStream().flush();
            return new String(socket.getInputStream().readAllBytes(),
                    java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private static HttpResponse<String> get(int port, String path) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String pem(X509Certificate cert) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private static X509Certificate selfSigned(KeyPair keyPair) throws Exception {
        X500Name dn = new X500Name("CN=example.com");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(dn, BigInteger.ONE,
                Date.from(now), Date.from(now.plus(90, ChronoUnit.DAYS)), dn, keyPair.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
