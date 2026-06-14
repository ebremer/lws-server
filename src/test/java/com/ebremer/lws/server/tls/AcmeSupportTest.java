package com.ebremer.lws.server.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
        ctx.addFilter(new FilterHolder(new HttpsRedirectFilter(8443)), "/*", EnumSet.of(DispatcherType.REQUEST));
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
            // Any other plaintext path is redirected (301) to HTTPS.
            HttpResponse<String> redirect = get(port, "/some/resource");
            assertEquals(301, redirect.statusCode());
            assertEquals("https://localhost:8443/some/resource",
                    redirect.headers().firstValue("Location").orElse(""));
        } finally {
            server.stop();
        }
    }

    @Test
    void buildsKeyStoreFromDomainKeyAndCertificateChain() throws Exception {
        Path dir = Files.createTempDirectory("lws-tls-test");
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "https://example.com");
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
