package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Properties;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * Cross-Origin Resource Sharing over the real stack (finding M7).
 *
 * <p>The server sent no {@code Access-Control-*} header anywhere, and because an
 * {@code Authorization} header makes an authenticated request non-simple, a browser sends a
 * preflight {@code OPTIONS} first — with no credentials on it. That preflight was answered by the
 * resource servlet, which (correctly, since M-era hardening stopped {@code OPTIONS} being an
 * existence oracle) refuses an anonymous caller who cannot read the target. So no browser
 * application on another origin could complete a single request here, which also made
 * {@code acl:origin} — implemented by the WAC engine — unreachable.
 *
 * @author Erich Bremer
 */
class CorsTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}.
     */
    private static final Path tempDir = TestDirs.create();

    private static final String APP = "https://app.example";
    private static final String OTHER = "https://evil.example";

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;
    private static String ownerToken;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        DidKeyTool.Minted owner = DidKeyTool.mint(null, 3600, baseUrl);
        ownerToken = owner.token();

        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.owners", owner.did());
        p.setProperty("lws.data-dir", tempDir.toString());
        p.setProperty("lws.cors.allowed-origins", APP);
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        http = HttpClient.newHttpClient();
        // An existing, owner-only resource: a preflight against a path that does not exist would be
        // answered 204 even pre-fix (there is nothing to be an oracle about), so the discriminating
        // case has to be a real one.
        assertEquals(201, authed("PUT", "/cors-target", "hello").statusCode());
    }

    @AfterAll
    static void stop() throws Exception {
        if (server != null) {
            server.stop();
        }
        if (components != null) {
            components.close();
        }
    }

    /**
     * The load-bearing test: a preflight is answered {@code 204} with the headers a browser needs,
     * <em>without</em> credentials and without reaching the resource servlet.
     *
     * <p>Against the pre-fix code this is a {@code 401}: the preflight carries no
     * {@code Authorization}, the target exists, the storage has an owner and is not public-read, and
     * {@code handleOptions} refuses an anonymous caller who cannot read the target. Which is to say
     * the pre-fix failure is not "a header was missing" but "the browser never got to send the real
     * request at all".
     */
    @Test
    void aPreflightIsAnsweredWithoutCredentials() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/cors-target"))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .header("Origin", APP)
                .header("Access-Control-Request-Method", "PUT")
                .header("Access-Control-Request-Headers", "authorization, content-type")
                .build(), HttpResponse.BodyHandlers.ofString());

        assertEquals(204, r.statusCode());
        assertEquals(APP, r.headers().firstValue("Access-Control-Allow-Origin").orElse(""));
        String methods = r.headers().firstValue("Access-Control-Allow-Methods").orElse("");
        assertTrue(methods.contains("PUT") && methods.contains("PATCH") && methods.contains("DELETE"),
                methods);
        String headers = r.headers().firstValue("Access-Control-Allow-Headers").orElse("")
                .toLowerCase(java.util.Locale.ROOT);
        for (String needed : new String[] {"authorization", "dpop", "if-match", "slug", "link",
                "lws-purpose", "content-type"}) {
            assertTrue(headers.contains(needed), needed + " must be allowed: " + headers);
        }
        assertTrue(r.headers().allValues("Vary").stream().anyMatch(v -> v.contains("Origin")),
                "the response varies by Origin and must say so");
        // Never: the API authenticates with a header the script supplies, not an ambient cookie.
        assertTrue(r.headers().firstValue("Access-Control-Allow-Credentials").isEmpty());
    }

    /**
     * An actual cross-origin request gets the allow header and — the part that makes the protocol
     * usable — the list of response headers a script is permitted to read. Without
     * {@code Expose-Headers} a browser client cannot see {@code ETag}, so it cannot make a
     * conditional write, which this server requires of every replacement.
     */
    @Test
    void anAllowedOriginCanReadTheProtocolHeaders() throws Exception {
        assertEquals(201, authed("PUT", "/cors-doc", "hello").statusCode());

        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/cors-doc"))
                .header("Origin", APP).header("Authorization", "Bearer " + ownerToken)
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode());
        assertEquals(APP, r.headers().firstValue("Access-Control-Allow-Origin").orElse(""));
        String exposed = r.headers().firstValue("Access-Control-Expose-Headers").orElse("")
                .toLowerCase(java.util.Locale.ROOT);
        assertTrue(exposed.contains("etag"), exposed);
        assertTrue(exposed.contains("location"), exposed);
        assertTrue(exposed.contains("www-authenticate"), exposed);
        assertTrue(exposed.contains("dpop-nonce"), exposed);
    }

    /**
     * {@code Vary: Origin} survives a content-negotiated response.
     *
     * <p>The CORS filter {@code add}s it and the servlets then declared {@code Vary: Accept} with
     * {@code setHeader}, which <em>replaces</em>. So every response that varies by both said it
     * varied only by {@code Accept} — and a shared cache keyed on {@code Accept} alone could store
     * an allowed origin's {@code Access-Control-Allow-Origin} and serve it to a request from a
     * different origin, which is the whole point of the header being there. Against the pre-fix code
     * the {@code Origin} assertion fails on every one of these.
     */
    @Test
    void varyOriginSurvivesContentNegotiation() throws Exception {
        assertEquals(201, http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/cors-rdf"))
                .header("Authorization", "Bearer " + ownerToken)
                .header("Content-Type", "text/turtle")
                .PUT(HttpRequest.BodyPublishers.ofString("<#it> <http://schema.org/name> \"x\" ."))
                .build(), HttpResponse.BodyHandlers.ofString()).statusCode());

        for (String path : new String[] {"/cors-rdf", "/", "/.lws/storage-description"}) {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .header("Origin", APP).header("Authorization", "Bearer " + ownerToken)
                    .header("Accept", "text/turtle").GET().build(), HttpResponse.BodyHandlers.ofString());
            String vary = String.join(", ", r.headers().allValues("Vary"));
            assertTrue(vary.contains("Origin"), path + " must still vary by Origin: " + vary);
            assertTrue(vary.contains("Accept"), path + " must still vary by Accept: " + vary);
        }
    }

    /** An origin that is not on the list gets the ordinary response and no allow header. */
    @Test
    void anUnlistedOriginIsNotAllowed() throws Exception {
        HttpResponse<String> preflight = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/anything"))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .header("Origin", OTHER)
                .header("Access-Control-Request-Method", "GET")
                .build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(preflight.headers().firstValue("Access-Control-Allow-Origin").isEmpty(),
                "an unlisted origin gets no allow header, so the browser blocks it");
        assertTrue(preflight.headers().allValues("Vary").stream().anyMatch(v -> v.contains("Origin")),
                "and the refusal still varies by Origin, so a cache cannot serve it to an allowed one");
    }

    /**
     * {@code Origin: null} — a sandboxed iframe, a {@code data:} document, a cross-origin redirect —
     * is never an origin an operator listed, so it is never allowed.
     */
    @Test
    void theOpaqueOriginIsNeverAllowed() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/anything"))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .header("Origin", "null")
                .header("Access-Control-Request-Method", "GET")
                .build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(r.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
    }

    /**
     * The console is excluded from CORS outright. It authenticates with a session cookie, and while
     * never sending {@code Allow-Credentials} already means a cross-origin fetch of it is anonymous,
     * this keeps that true if the credentials decision is ever revisited.
     */
    @Test
    void theConsoleIsExcluded() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/app/browse"))
                .header("Origin", APP).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(r.headers().firstValue("Access-Control-Allow-Origin").isEmpty(),
                "the management console is not a cross-origin API");
    }

    /** A same-origin request (no {@code Origin} header) is untouched. */
    @Test
    void requestsWithoutAnOriginAreUnchanged() throws Exception {
        HttpResponse<String> r = authed("GET", "/", null);
        assertEquals(200, r.statusCode());
        assertTrue(r.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
    }

    // ----- configuration -----

    /**
     * {@code *} plus open mode is refused at startup.
     *
     * <p>It is the shape a browser-app developer reaches for first — a loopback base URI,
     * {@code lws.dev.open=true} to skip configuring an owner, and {@code *} to make the app work —
     * and in open mode every read <em>and every write</em> is permitted anonymously. The authority is
     * ambient, so there is no credential an attacking page would have to hold and "we never send
     * Allow-Credentials" protects nothing: {@code *} would hand the whole storage to any website the
     * developer visits.
     */
    @Test
    void wildcardCorsIsRefusedInOpenMode() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://localhost:8080");
        p.setProperty("lws.dev.open", "true");
        p.setProperty("lws.cors.allowed-origins", "*");
        LwsConfigurationException e =
                assertThrows(LwsConfigurationException.class, () -> LwsConfiguration.of(p));
        assertTrue(e.getMessage().contains("lws.cors.allowed-origins"), e.getMessage());
        assertTrue(e.getMessage().contains("open mode"), e.getMessage());
    }

    /** With real authorization, {@code *} is a choice an operator is allowed to make. */
    @Test
    void wildcardCorsIsPermittedWithOwners() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "https://storage.example");
        p.setProperty("lws.owners", "https://alice.example/profile#me");
        p.setProperty("lws.cors.allowed-origins", "*");
        LwsConfiguration config = LwsConfiguration.of(p);
        assertTrue(config.corsAllowsAnyOrigin());
        assertTrue(config.corsEnabled());
    }

    /** An allowed origin is a scheme and a host, not a URL with a path. */
    @Test
    void allowedOriginsAreValidated() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "https://storage.example");
        p.setProperty("lws.owners", "https://alice.example/profile#me");
        p.setProperty("lws.cors.allowed-origins", "https://app.example/some/path");
        LwsConfigurationException e =
                assertThrows(LwsConfigurationException.class, () -> LwsConfiguration.of(p));
        assertTrue(e.getMessage().contains("no path"), e.getMessage());
    }

    /**
     * A default port written explicitly still matches. A browser's serialized origin omits it, so an
     * operator who writes {@code https://app.example:443} would otherwise get a configuration that
     * validates, starts, and silently refuses every request from that origin.
     */
    @Test
    void defaultPortsAreNormalisedOnBothSides() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "https://storage.example");
        p.setProperty("lws.owners", "https://alice.example/profile#me");
        p.setProperty("lws.cors.allowed-origins", "https://app.example:443, http://dev.example:80");
        LwsConfiguration config = LwsConfiguration.of(p);
        assertTrue(config.corsAllowedOrigins().contains("https://app.example"),
                config.corsAllowedOrigins().toString());
        assertTrue(config.corsAllowedOrigins().contains("http://dev.example"),
                config.corsAllowedOrigins().toString());
        // A non-default port is untouched.
        assertEquals("https://app.example:8443",
                LwsConfiguration.normalizeOrigin("https://APP.example:8443"));
    }

    /** No origins configured means the filter is never installed and nothing changes. */
    @Test
    void corsIsOffByDefault() {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "https://storage.example");
        p.setProperty("lws.owners", "https://alice.example/profile#me");
        LwsConfiguration config = LwsConfiguration.of(p);
        assertFalse(config.corsEnabled());
        assertTrue(config.corsAllowedOrigins().isEmpty());
    }

    // ----- helpers -----

    private static HttpResponse<String> authed(String method, String path, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + ownerToken);
        if (body != null) {
            b.header("Content-Type", "text/plain");
        }
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
