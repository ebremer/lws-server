package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * A conditional write is a compare-and-swap, not a check-then-write (findings H23 and M18).
 *
 * <p>The entity-tag a client conditions on has to be compared against the stored one <em>inside</em>
 * the transaction that performs the write. Evaluated in an earlier transaction of its own, the
 * comparison proves nothing: every writer holding the same tag passes it, every writer then commits,
 * and each silently discards the one before it — each of them answered {@code 204} under a
 * precondition it believed it had satisfied. These tests race a group of writers that all start from
 * the same tag and assert that exactly one of them is allowed to land.
 *
 * @author Erich Bremer
 */
class ConditionalWriteTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}. It used to be a bare
     * {@code createTempDirectory} that nothing ever removed, and the leak once filled a disk.
     */
    private static final Path tempDir = TestDirs.create();

    /** How many writers race for each resource. More than two, so a partial fix still fails. */
    private static final int WRITERS = 8;

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
        // Open mode: this class asserts concurrency behaviour, not authorization outcomes,
        // so it opts in to the development posture rather than configuring an owner.
        p.setProperty("lws.dev.open", "true");
        p.setProperty("lws.data-dir", tempDir.toString());
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

    @Test
    void concurrentConditionalPutsLetExactlyOneWriterWin() throws Exception {
        assertEquals(201, send("PUT", "/race", "<#it> <http://schema.org/name> \"v1\" .",
                "Content-Type", "text/turtle").statusCode());
        String etag = etagOf("/race");

        List<Integer> statuses = race("PUT", "/race", "<#it> <http://schema.org/name> \"v2\" .",
                "Content-Type", "text/turtle", "If-Match", etag);

        assertExactlyOneWinner(statuses);
    }

    @Test
    void concurrentConditionalPatchesLetExactlyOneWriterWin() throws Exception {
        assertEquals(201, send("PUT", "/race-patch", "{\"n\":1}", "Content-Type", "application/json").statusCode());
        String etag = etagOf("/race-patch");

        List<Integer> statuses = race("PATCH", "/race-patch", "{\"n\":2}",
                "Content-Type", "application/merge-patch+json", "If-Match", etag);

        assertExactlyOneWinner(statuses);
    }

    @Test
    void concurrentConditionalDeletesLetExactlyOneWriterWin() throws Exception {
        assertEquals(201, send("PUT", "/race-delete", "<#it> <http://schema.org/name> \"v1\" .",
                "Content-Type", "text/turtle").statusCode());
        String etag = etagOf("/race-delete");

        List<Integer> statuses = race("DELETE", "/race-delete", null, "If-Match", etag);

        assertEquals(1, statuses.stream().filter(s -> s == 204).count(),
                "exactly one deleter may win: " + statuses);
        // A loser is refused either because the tag it holds is stale (412) or because the winner
        // has already removed the resource (404). Neither may be a success.
        assertTrue(statuses.stream().allMatch(s -> s == 204 || s == 412 || s == 404),
                "losers must be refused, not silently accepted: " + statuses);
    }

    /** The same race against a resource's linkset (metadata) resource — finding M18. */
    @Test
    void concurrentConditionalLinksetPatchesLetExactlyOneWriterWin() throws Exception {
        assertEquals(201, send("PUT", "/race-meta", "<#it> <http://schema.org/name> \"v1\" .",
                "Content-Type", "text/turtle").statusCode());
        String etag = etagOf("/race-meta.meta");

        List<Integer> statuses = race("PATCH", "/race-meta.meta",
                "{\"describedby\":[{\"href\":\"https://shapes.example/S\"}]}",
                "Content-Type", "application/merge-patch+json", "If-Match", etag);

        assertExactlyOneWinner(statuses);
    }

    /**
     * {@code If-Match} against a resource that does not exist is never satisfied — including
     * {@code If-Match: *}, whose meaning is "the resource must have a current representation"
     * (RFC 9110 section 13.1.1). Letting such a PUT create instead would be the lost update the
     * header was sent to prevent: the version the client meant to replace was deleted in the
     * window, and the client would never learn that its "replacement" was a resurrection.
     */
    @Test
    void ifMatchAgainstAMissingResourceIsRefused() throws Exception {
        assertEquals(412, send("PUT", "/never-existed", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle", "If-Match", "\"deadbeef00000000\"").statusCode());
        assertEquals(412, send("PUT", "/never-existed", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle", "If-Match", "*").statusCode());
        assertEquals(404, send("GET", "/never-existed", null).statusCode());

        // The same path, deleted between the client's read and its write, must not be resurrected.
        assertEquals(201, send("PUT", "/vanishes", "<#it> <http://schema.org/name> \"v1\" .",
                "Content-Type", "text/turtle").statusCode());
        String etag = etagOf("/vanishes");
        assertEquals(204, send("DELETE", "/vanishes", null, "If-Match", etag).statusCode());
        assertEquals(412, send("PUT", "/vanishes", "<#it> <http://schema.org/name> \"v2\" .",
                "Content-Type", "text/turtle", "If-Match", etag).statusCode());

        // An unconditional PUT still creates: only a client that named a version is refused.
        assertEquals(201, send("PUT", "/vanishes", "<#it> <http://schema.org/name> \"v2\" .",
                "Content-Type", "text/turtle").statusCode());
    }

    // ----- helpers -----

    private static void assertExactlyOneWinner(List<Integer> statuses) {
        assertEquals(1, statuses.stream().filter(s -> s == 204).count(),
                "exactly one writer may win: " + statuses);
        assertEquals(WRITERS - 1, statuses.stream().filter(s -> s == 412).count(),
                "every losing writer must be refused with 412: " + statuses);
    }

    private static String etagOf(String path) throws Exception {
        HttpResponse<String> r = send("GET", path, null);
        assertEquals(200, r.statusCode(), path);
        return r.headers().firstValue("ETag").orElseThrow(() -> new AssertionError("no ETag on " + path));
    }

    /**
     * Fire {@link #WRITERS} identical requests at once and return their status codes. Every writer
     * is held at a latch until all of them are ready, so they all reach the server carrying the same
     * entity-tag, which is the condition the compare-and-swap has to survive.
     */
    private static List<Integer> race(String method, String path, String body, String... headers) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(WRITERS);
        try {
            CountDownLatch ready = new CountDownLatch(WRITERS);
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Integer>> pending = new ArrayList<>();
            for (int i = 0; i < WRITERS; i++) {
                pending.add(pool.submit(() -> {
                    ready.countDown();
                    go.await();
                    return send(method, path, body, headers).statusCode();
                }));
            }
            assertTrue(ready.await(30, TimeUnit.SECONDS), "writers never became ready");
            go.countDown();
            List<Integer> statuses = new ArrayList<>();
            for (Future<Integer> f : pending) {
                statuses.add(f.get(60, TimeUnit.SECONDS));
            }
            return statuses;
        } finally {
            pool.shutdownNow();
        }
    }

    private static HttpResponse<String> send(String method, String path, String body, String... headers)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path));
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
