package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
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

/**
 * Finding N5 — a stored linkset cannot be grown past what a reader can handle.
 *
 * <p>{@code JsonLimits} bounds one <em>request body</em>, and that bound does not compose. A JSON
 * Patch addresses by JSON Pointer, so a shallow patch reaches an arbitrarily deep position in what
 * is already stored and adds to it there. Repeating it grows the stored document without limit while
 * every individual request stays comfortably inside the bound — and nothing bounded the merged
 * result before it was stored, or the stored literal when it was read back.
 *
 * <p>Measured against the pre-fix code on this classpath: the provider enforces its own nesting cap
 * at 1,000 and reports it as a bare {@code java.lang.RuntimeException}, which the read path's
 * {@code catch (JsonException | IllegalStateException)} let straight through; on a servlet-sized
 * stack it is a {@link StackOverflowError} instead, which is an {@code Error} and escapes further
 * still. Either way the resource's {@code .meta} became a permanent {@code 500} for every reader,
 * its owner included, from a handful of small authorized writes — and the provider's writer has no
 * cap at all, so a document could be stored that could never be read back.
 *
 * <p>The second half is the size: RFC 6902 {@code copy} from the whole document doubles it while
 * adding a single level, so a depth bound on its own still permits sixty doublings.
 *
 * @author Erich Bremer
 */
class StoredLinksetDepthTest {

    /** See {@link TestDirs}: {@code @TempDir} cannot be used with a memory-mapped TDB2 dataset. */
    private static final Path tempDir = TestDirs.create();

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        // Open mode: this class asserts a resource limit, not an authorization outcome. The point
        // of the finding is that the writes are AUTHORIZED — the damage is done by a client that is
        // allowed to write the metadata it is destroying.
        p.setProperty("lws.dev.open", "true");
        p.setProperty("lws.data-dir", tempDir.toString());
        p.setProperty("lws.linkset.max-bytes", "65536");
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        http = HttpClient.newHttpClient();
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
     * The regression. Each request is trivially small and individually inside the body bound; what
     * grows is the composition. The run must be refused before the stored document stops being
     * readable, and the resource must still work afterwards.
     */
    @Test
    void repeatedPatchesCannotDeepenTheStoredLinksetPastTheBound() throws Exception {
        assertEquals(201, send("PUT", "/deep", "x", "Content-Type", "text/plain").statusCode());

        String pointer = "/example";
        assertApplied(patch("/deep.meta",
                "[{\"op\":\"add\",\"path\":\"" + pointer + "\",\"value\":" + nested(40) + "}]"));

        boolean refused = false;
        for (int round = 0; round < 40 && !refused; round++) {
            pointer += "/a".repeat(40);
            int status = patch("/deep.meta",
                    "[{\"op\":\"add\",\"path\":\"" + pointer + "\",\"value\":" + nested(40) + "}]");
            if (status == 400 || status == 409) {
                refused = true;
            } else {
                assertApplied(status, "unexpected status while deepening the stored linkset");
            }
        }
        assertTrue(refused, "the stored linkset grew without ever being refused");

        // ...and what is stored is still readable, and still writable.
        HttpResponse<String> get = send("GET", "/deep.meta", null);
        assertEquals(200, get.statusCode(), "the stored linkset must still be readable");
        assertNotNull(get.body());
        assertTrue(get.body().contains("anchor"), "the linkset must still render its server links");
        assertApplied(patch("/deep.meta", "[{\"op\":\"add\",\"path\":\"/note\",\"value\":\"ok\"}]"),
                "an ordinary patch must still succeed after the refusal");
    }

    /**
     * The size half. {@code copy} from {@code ""} duplicates the whole document into a new member:
     * one level deeper, twice the size. A depth bound alone permits sixty of those, which is heap
     * exhaustion inside the store's single global writer lock.
     */
    @Test
    void aCopyPatchCannotDoubleTheStoredLinksetWithoutLimit() throws Exception {
        assertEquals(201, send("PUT", "/wide", "x", "Content-Type", "text/plain").statusCode());
        assertApplied(patch("/wide.meta",
                "[{\"op\":\"add\",\"path\":\"/seed\",\"value\":\"" + "0123456789".repeat(200) + "\"}]"));

        boolean refused = false;
        for (int round = 0; round < 30 && !refused; round++) {
            int status = patch("/wide.meta",
                    "[{\"op\":\"copy\",\"from\":\"\",\"path\":\"/dup" + round + "\"}]");
            if (status == 400 || status == 409) {
                refused = true;
            } else {
                assertApplied(status, "unexpected status while doubling the stored linkset");
            }
        }
        assertTrue(refused, "the stored linkset doubled unboundedly");
        assertEquals(200, send("GET", "/wide.meta", null).statusCode());
    }

    /** A linkset at the bound still round-trips: what the server hands out, it accepts back. */
    @Test
    void aLinksetTheServerRendersIsOneItWillAcceptBack() throws Exception {
        assertEquals(201, send("PUT", "/round", "x", "Content-Type", "text/plain").statusCode());
        assertApplied(patch("/round.meta",
                "[{\"op\":\"add\",\"path\":\"/example\",\"value\":" + nested(60) + "}]"));

        HttpResponse<String> get = send("GET", "/round.meta", null);
        assertEquals(200, get.statusCode());
        String etag = get.headers().firstValue("ETag").orElse(null);
        assertNotNull(etag, "the linkset must carry an entity-tag");

        int put = send("PUT", "/round.meta", get.body(),
                "Content-Type", "application/linkset+json", "If-Match", etag).statusCode();
        assertTrue(put == 200 || put == 204,
                "the server refused a linkset it had just rendered itself: " + put);
    }

    /** A linkset write that took effect: the servlet answers 204, or 200 when it returns the body. */
    private static void assertApplied(int status) {
        assertApplied(status, "the linkset write was expected to be applied");
    }

    private static void assertApplied(int status, String why) {
        assertTrue(status == 200 || status == 204, why + " (status " + status + ")");
    }

    private static String nested(int depth) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            sb.append("{\"a\":");
        }
        sb.append("1");
        sb.append("}".repeat(depth));
        return sb.toString();
    }

    /** PATCH the linkset with the entity-tag it currently carries, and return the status. */
    private static int patch(String path, String body) throws Exception {
        String etag = send("GET", path, null).headers().firstValue("ETag").orElse(null);
        if (etag == null) {
            return fail("no entity-tag on " + path);
        }
        return send("PATCH", path, body,
                "Content-Type", "application/json-patch+json", "If-Match", etag).statusCode();
    }

    private static HttpResponse<String> send(String method, String path, String body, String... headers)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path));
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        b.method(method, body == null
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
