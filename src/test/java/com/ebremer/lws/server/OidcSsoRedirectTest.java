package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.CookieManager;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.auth.MockOidcProvider;

/**
 * Verifies the interactive browser SSO entry point: with OIDC configured, an unauthenticated
 * {@code GET /app/oidc-login} is redirected by the pac4j security filter to the identity
 * provider's authorization endpoint (the start of the OpenID Connect code flow).
 *
 * @author Erich Bremer
 */
class OidcSsoRedirectTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}. It used to be a bare
     * {@code createTempDirectory} that nothing ever removed, and the leak once filled a disk.
     */
    private static final Path tempDir = TestDirs.create();

    private static MockOidcProvider idp;
    private static Server lws;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;

    @BeforeAll
    static void start() throws Exception {
        idp = new MockOidcProvider();
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        // An owner, because this class asserts nothing about authorization and the
        // development posture now has to be asked for explicitly.
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        p.setProperty("lws.data-dir", tempDir.toString());
        p.setProperty("lws.oidc.discovery-uri", idp.discoveryUri());
        p.setProperty("lws.oidc.client-id", "lws-client");
        p.setProperty("lws.oidc.client-secret", "test-secret");
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        lws = new Server(port);
        lws.setHandler(JettyLauncher.buildHandler(components, config));
        lws.start();
        http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(new CookieManager())
                .build();
    }

    @AfterAll
    static void stop() throws Exception {
        if (lws != null) {
            lws.stop();
        }
        if (components != null) {
            components.close();
        }
        if (idp != null) {
            idp.close();
        }
    }

    @Test
    void redirectsToProviderAuthorizationEndpoint() throws Exception {
        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl + "/app/oidc-login")).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(302, response.statusCode(), "SSO entry point should redirect to the IdP");
        String location = response.headers().firstValue("Location").orElse("");
        assertTrue(location.startsWith(idp.issuer() + "/authorize"),
                "should redirect to the provider authorization endpoint, was: " + location);
        assertTrue(location.contains("client_id=lws-client"), location);
        assertTrue(location.contains("response_type=code"), location);
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
