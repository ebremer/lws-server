package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
 * The management console under a path prefix: {@code lws.base-uri=http://host/lws}, with the proxy
 * that strips {@code /lws} simulated by requesting the unprefixed path directly.
 *
 * <p>The console's redirects used to leave the prefix out, sending the browser off the storage to
 * {@code /app/browse}; its session cookie was scoped to the whole host; and an anonymous visitor to
 * a storage that is not publicly readable got a {@code 500} instead of the page's error box.
 *
 * @author Erich Bremer
 */
class BasePathConsoleTest {

    /** See {@link TestDirs}: {@code @TempDir} cannot be used with a memory-mapped TDB2 dataset. */
    private static final Path tempDir = TestDirs.create();

    private static Server server;
    private static LwsComponents components;
    private static String origin;
    private static final HttpClient http = HttpClient.newHttpClient(); // follows no redirects

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        origin = "http://localhost:" + port;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", origin + "/lws");
        p.setProperty("lws.data-dir", tempDir.toString());
        p.setProperty("lws.owners", DidKeyTool.mint(null, 3600, origin + "/lws").did());
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
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

    @Test
    void consoleRedirectsKeepTheBasePath() throws Exception {
        HttpResponse<String> r = get("/app/");
        assertTrue(r.statusCode() / 100 == 3, "status " + r.statusCode());
        String location = r.headers().firstValue("Location").orElseThrow();
        assertTrue(location.startsWith(origin + "/lws/app/"), location);
    }

    @Test
    void sessionCookieIsScopedToTheBasePath() throws Exception {
        HttpResponse<String> r = get("/app/login");
        String cookie = r.headers().allValues("Set-Cookie").stream()
                .filter(c -> c.startsWith("JSESSIONID=")).findFirst().orElseThrow();
        assertTrue(cookie.contains("Path=/lws;") || cookie.endsWith("Path=/lws"), cookie);
    }

    @Test
    void anAnonymousVisitorGetsThePageNotAServerError() throws Exception {
        assertEquals(200, get("/app/browse").statusCode());
    }

    @Test
    void theStorageApiIsUnaffected() throws Exception {
        HttpResponse<String> r = get("/");
        assertEquals(200, r.statusCode());
        assertTrue(r.body().contains("\"id\":\"" + origin + "/lws/\""), r.body());
    }

    private static HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(origin + path)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
