package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * Verifies the two security-critical guarantees of the search services against a live server: every
 * response is filtered to the requesting principal's current read authorization (so an unauthorized
 * client cannot even learn that a type or resource exists), and the standard pagination model with
 * its {@code Link} relations. Runs in owner mode with a self-signed {@code did:key} owner; resources
 * are private by default, so the owner sees them and an anonymous client sees nothing.
 *
 * @author Erich Bremer
 */
class SearchIndexAuthzTest {

    private static final String SECRET = "https://schema.org/Secret";
    private static final String INDEX = "/.lws/type-index";
    private static final String SEARCH = "/.lws/type-search";

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;
    private static String ownerToken;

    @BeforeAll
    static void start() throws Exception {
        DidKeyTool.Minted owner = DidKeyTool.mint(null, 3600, null);
        ownerToken = owner.token();

        int port = freePort();
        baseUrl = "http://localhost:" + port;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.data-dir", Files.createTempDirectory("lws-search-authz").toString());
        p.setProperty("lws.owners", owner.did());
        p.setProperty("lws.public-read", "false");       // resources private unless owner-read
        p.setProperty("lws.search-index.page-size", "2"); // force multi-page results
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        http = HttpClient.newHttpClient();

        for (String name : List.of("/s1", "/s2", "/s3")) {
            put(name, "<> a <" + SECRET + "> .");
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
    void ownerSeesPrivateTypesAndResources() {
        // Owner: the type and all three resources are visible (totalItems counts the full authorized view).
        assertEquals(3, getLws(baseUrl + SEARCH + "?type=" + enc(SECRET), ownerToken).getInt("totalItems"));
        Set<String> ids = new HashSet<>();
        ids.addAll(ids(getLws(baseUrl + SEARCH + "?type=" + enc(SECRET) + "&page=1", ownerToken)));
        ids.addAll(ids(getLws(baseUrl + SEARCH + "?type=" + enc(SECRET) + "&page=2", ownerToken)));
        assertEquals(Set.of(baseUrl + "/s1", baseUrl + "/s2", baseUrl + "/s3"), ids);
        assertTrue(indexTypes(ownerToken).contains(SECRET), "owner type index should include the private type");
    }

    @Test
    void anonymousCannotDiscoverPrivateTypesOrResources() {
        // Anonymous: no readable resources, so the search and the index are both empty -- the
        // existence of the resources and even of the type itself is not disclosed.
        assertEquals(0, getLws(baseUrl + SEARCH + "?type=" + enc(SECRET), null).getInt("totalItems"));
        assertEquals(0, getLws(baseUrl + INDEX, null).getInt("totalItems"));
        assertFalse(indexTypes(null).contains(SECRET), "anonymous must not learn the private type exists");
    }

    @Test
    void paginationExposesLinkRelations() throws Exception {
        HttpResponse<String> page1 = raw(baseUrl + SEARCH + "?type=" + enc(SECRET) + "&page=1", ownerToken);
        assertEquals(200, page1.statusCode());
        assertEquals(2, items(page1).size());
        assertTrue(hasRel(page1, "next"), "page 1 should link to next");
        assertTrue(hasRel(page1, "last"), "page 1 should link to last");

        HttpResponse<String> page2 = raw(baseUrl + SEARCH + "?type=" + enc(SECRET) + "&page=2", ownerToken);
        assertEquals(200, page2.statusCode());
        assertEquals(1, items(page2).size());
        assertTrue(hasRel(page2, "prev"), "page 2 should link to prev");
        assertTrue(hasRel(page2, "first"), "page 2 should link to first");

        // A page past the last is a stale/unknown pagination reference.
        assertEquals(404, raw(baseUrl + SEARCH + "?type=" + enc(SECRET) + "&page=3", ownerToken).statusCode());
    }

    // ----- helpers -----

    private static void put(String path, String turtle) throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "text/turtle").header("Authorization", "Bearer " + ownerToken)
                .PUT(HttpRequest.BodyPublishers.ofString(turtle)).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(201, r.statusCode(), "PUT " + path + " -> " + r.statusCode() + " " + r.body());
    }

    private static HttpResponse<String> raw(String url, String token) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).GET();
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static JsonObject getLws(String url, String token) {
        try {
            HttpResponse<String> r = raw(url, token);
            assertEquals(200, r.statusCode(), url + " -> " + r.statusCode() + " " + r.body());
            return Json.createReader(new StringReader(r.body())).readObject();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Set<String> indexTypes(String token) {
        // Walk every page of the type index so the assertion does not depend on page size.
        Set<String> all = new HashSet<>();
        int page = 1;
        while (true) {
            HttpResponse<String> r;
            try {
                r = raw(baseUrl + INDEX + "?page=" + page, token);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            if (r.statusCode() == 404) {
                break;
            }
            assertEquals(200, r.statusCode());
            JsonObject doc = Json.createReader(new StringReader(r.body())).readObject();
            all.addAll(ids(doc));
            if (page >= Math.max(1, (doc.getInt("totalItems") + 1) / 2)) {
                break;
            }
            page++;
        }
        return all;
    }

    private static Set<String> items(HttpResponse<String> r) {
        return ids(Json.createReader(new StringReader(r.body())).readObject());
    }

    private static Set<String> ids(JsonObject doc) {
        Set<String> out = new HashSet<>();
        for (JsonValue item : doc.getJsonArray("items")) {
            out.add(item.asJsonObject().getString("id"));
        }
        return out;
    }

    private static boolean hasRel(HttpResponse<String> r, String rel) {
        return r.headers().allValues("Link").stream().anyMatch(h -> h.contains("rel=\"" + rel + "\""));
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
