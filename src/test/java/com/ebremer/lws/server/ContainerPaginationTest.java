package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Tests container-listing pagination (lws10-core lws-media-type): with the page size set small, a
 * container with several members is split into pages carrying only the current page of {@code items}
 * while {@code totalItems} reflects the full membership, with {@code first}/{@code prev}/{@code next}/
 * {@code last} Link relations and a 404 for a page past the last.
 *
 * @author Erich Bremer
 */
class ContainerPaginationTest {

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
        p.setProperty("lws.data-dir", Files.createTempDirectory("lws-pagination").toString());
        p.setProperty("lws.container.page-size", "2");
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        http = HttpClient.newHttpClient();

        assertEquals(201, send("PUT", "/pag/", null, "Link", "<https://www.w3.org/ns/lws#Container>; rel=\"type\"")
                .statusCode());
        for (String name : List.of("c1", "c2", "c3", "c4", "c5")) {
            assertEquals(201, send("POST", "/pag/", "x", "Content-Type", "text/plain", "Slug", name).statusCode());
        }
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
    void listingIsPaginatedWithLinkRelations() throws Exception {
        // 5 members, page size 2 => 3 pages.
        HttpResponse<String> page1 = send("GET", "/pag/", null);
        assertEquals(200, page1.statusCode());
        assertTrue(page1.headers().firstValue("Content-Type").orElse("").startsWith("application/lws+json"));
        JsonObject doc1 = parse(page1.body());
        assertEquals(5, doc1.getInt("totalItems")); // full membership
        assertEquals(2, doc1.getJsonArray("items").size()); // current page only
        assertTrue(hasRel(page1, "first"), "first MUST be present");
        assertTrue(hasRel(page1, "next"), "next MUST be present before the last page");
        assertTrue(hasRel(page1, "last"));
        assertFalse(hasRel(page1, "prev"), "prev MUST be omitted on the first page");

        HttpResponse<String> page2 = send("GET", "/pag/?page=2", null);
        assertEquals(200, page2.statusCode());
        assertEquals(2, parse(page2.body()).getJsonArray("items").size());
        assertTrue(hasRel(page2, "prev") && hasRel(page2, "next") && hasRel(page2, "first") && hasRel(page2, "last"));

        HttpResponse<String> page3 = send("GET", "/pag/?page=3", null);
        assertEquals(200, page3.statusCode());
        assertEquals(1, parse(page3.body()).getJsonArray("items").size());
        assertTrue(hasRel(page3, "prev"), "prev present on the last page");
        assertFalse(hasRel(page3, "next"), "next MUST be omitted on the last page");

        // Every member appears exactly once across the pages.
        Set<String> all = new HashSet<>();
        all.addAll(ids(doc1));
        all.addAll(ids(parse(page2.body())));
        all.addAll(ids(parse(page3.body())));
        assertEquals(5, all.size());

        // A page past the last is not found; an invalid page is a bad request.
        assertEquals(404, send("GET", "/pag/?page=4", null).statusCode());
        assertEquals(400, send("GET", "/pag/?page=0", null).statusCode());
    }

    @Test
    void perPageEntityTagsDiffer() throws Exception {
        String etag1 = send("GET", "/pag/?page=1", null).headers().firstValue("ETag").orElseThrow();
        String etag2 = send("GET", "/pag/?page=2", null).headers().firstValue("ETag").orElseThrow();
        assertFalse(etag1.equals(etag2), "different pages are different representations");
        // A conditional re-request of the same page is Not Modified.
        assertEquals(304, send("GET", "/pag/?page=1", null, "If-None-Match", etag1).statusCode());
    }

    // ----- helpers -----

    private static HttpResponse<String> send(String method, String path, String body, String... headers)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path));
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static boolean hasRel(HttpResponse<String> r, String rel) {
        return r.headers().allValues("Link").stream().anyMatch(h -> h.contains("rel=\"" + rel + "\""));
    }

    private static Set<String> ids(JsonObject doc) {
        Set<String> out = new HashSet<>();
        for (JsonValue item : doc.getJsonArray("items")) {
            out.add(item.asJsonObject().getString("id"));
        }
        return out;
    }

    private static JsonObject parse(String json) {
        return Json.createReader(new StringReader(json)).readObject();
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
