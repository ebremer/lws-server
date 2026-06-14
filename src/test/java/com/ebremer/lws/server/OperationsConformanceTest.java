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
import java.util.List;
import java.util.Properties;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Conformance tests for the lws10-core operations and processes that are HTTP-observable: the
 * lws+json container representation and its content negotiation, byte-range requests, conditional
 * PUT (428/412), the metadata Link relations (rel="up"/"linkset"), the linkset metadata resource
 * (read, OPTIONS, conditional PATCH/PUT), linkset removal on delete, and RFC 9457 problem+json.
 *
 * @author Erich Bremer
 */
class OperationsConformanceTest {

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
        p.setProperty("lws.data-dir", Files.createTempDirectory("lws-ops").toString());
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
    void containerRepresentationIsLwsJsonAndNegotiable() throws Exception {
        assertEquals(201, send("PUT", "/cnt/", null, "Link", "<https://www.w3.org/ns/lws#Container>; rel=\"type\"")
                .statusCode());
        assertEquals(201, send("POST", "/cnt/", "hi there", "Content-Type", "text/plain", "Slug", "note.txt")
                .statusCode());

        HttpResponse<String> json = send("GET", "/cnt/", null);
        assertEquals(200, json.statusCode());
        assertTrue(json.headers().firstValue("Content-Type").orElse("").startsWith("application/lws+json"));
        JsonObject doc = parse(json.body());
        assertEquals("Container", doc.getString("type"));
        assertEquals(baseUrl + "/cnt/", doc.getString("id"));
        assertEquals(1, doc.getInt("totalItems"));
        JsonObject item = doc.getJsonArray("items").getJsonObject(0);
        assertEquals(baseUrl + "/cnt/note.txt", item.getString("id"));
        assertEquals("DataResource", item.getString("type"));
        assertEquals("text/plain", item.getString("mediaType")); // MUST for DataResources
        assertEquals(8, item.getJsonNumber("size").longValue());
        assertTrue(item.containsKey("modified"));

        // The Content-Type is echoed across the JSON family (same body); text/turtle yields RDF.
        assertTrue(send("GET", "/cnt/", null, "Accept", "application/json").headers()
                .firstValue("Content-Type").orElse("").startsWith("application/json"));
        assertTrue(send("GET", "/cnt/", null, "Accept", "application/ld+json").headers()
                .firstValue("Content-Type").orElse("").startsWith("application/ld+json"));
        HttpResponse<String> turtle = send("GET", "/cnt/", null, "Accept", "text/turtle");
        assertTrue(turtle.headers().firstValue("Content-Type").orElse("").startsWith("text/turtle"));
        assertTrue(turtle.body().contains("/cnt/note.txt"));
    }

    @Test
    void byteRangeRequestsAreSupported() throws Exception {
        assertEquals(201, send("PUT", "/range.bin", "0123456789", "Content-Type", "application/octet-stream")
                .statusCode());

        HttpResponse<String> full = send("GET", "/range.bin", null);
        assertEquals(200, full.statusCode());
        assertEquals("bytes", full.headers().firstValue("Accept-Ranges").orElse(""));

        HttpResponse<String> head = send("GET", "/range.bin", null, "Range", "bytes=0-3");
        assertEquals(206, head.statusCode());
        assertEquals("bytes 0-3/10", head.headers().firstValue("Content-Range").orElse(""));
        assertEquals("0123", head.body());

        assertEquals("56789", send("GET", "/range.bin", null, "Range", "bytes=5-").body());
        assertEquals("89", send("GET", "/range.bin", null, "Range", "bytes=-2").body());

        HttpResponse<String> unsatisfiable = send("GET", "/range.bin", null, "Range", "bytes=50-60");
        assertEquals(416, unsatisfiable.statusCode());
        assertEquals("bytes */10", unsatisfiable.headers().firstValue("Content-Range").orElse(""));
    }

    @Test
    void replacingAResourceIsConditional() throws Exception {
        assertEquals(201, send("PUT", "/cput", "<#it> <http://schema.org/name> \"v1\" .",
                "Content-Type", "text/turtle").statusCode());

        // Unconditional replacement is rejected.
        assertEquals(428, send("PUT", "/cput", "<#it> <http://schema.org/name> \"v2\" .",
                "Content-Type", "text/turtle").statusCode());

        String etag = send("GET", "/cput", null).headers().firstValue("ETag").orElseThrow();
        // Stale precondition fails.
        assertEquals(412, send("PUT", "/cput", "<#it> <http://schema.org/name> \"v2\" .",
                "Content-Type", "text/turtle", "If-Match", "\"deadbeef00000000\"").statusCode());
        // Correct precondition succeeds.
        assertEquals(204, send("PUT", "/cput", "<#it> <http://schema.org/name> \"v2\" .",
                "Content-Type", "text/turtle", "If-Match", etag).statusCode());
    }

    @Test
    void responsesCarryMetadataLinkRelations() throws Exception {
        assertEquals(201, send("PUT", "/links", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());

        List<String> links = send("GET", "/links", null).headers().allValues("Link");
        assertTrue(links.stream().anyMatch(l -> l.contains(baseUrl + "/") && l.contains("rel=\"up\"")), links.toString());
        assertTrue(links.stream().anyMatch(l ->
                l.contains(baseUrl + "/links.meta") && l.contains("rel=\"linkset\"")), links.toString());

        // The storage root has no parent: rel="up" must be absent, but rel="linkset" present.
        List<String> rootLinks = send("GET", "/", null, "Accept", "text/turtle").headers().allValues("Link");
        assertFalse(rootLinks.stream().anyMatch(l -> l.contains("rel=\"up\"")), rootLinks.toString());
        assertTrue(rootLinks.stream().anyMatch(l -> l.contains("rel=\"linkset\"")), rootLinks.toString());
    }

    @Test
    void linksetResourceReadAndConditionalWrite() throws Exception {
        assertEquals(201, send("PUT", "/lset", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());

        HttpResponse<String> get = send("GET", "/lset.meta", null);
        assertEquals(200, get.statusCode());
        assertTrue(get.headers().firstValue("Content-Type").orElse("").startsWith("application/linkset+json"));
        assertTrue(get.headers().firstValue("Accept-Patch").orElse("").contains("merge-patch+json"));
        String etag = get.headers().firstValue("ETag").orElseThrow();
        JsonObject anchor = parse(get.body()).getJsonArray("linkset").getJsonObject(0);
        assertEquals(baseUrl + "/lset", anchor.getString("anchor"));
        assertEquals("https://www.w3.org/ns/lws#DataResource",
                anchor.getJsonArray("type").getJsonObject(0).getString("href"));
        assertEquals(baseUrl + "/", anchor.getJsonArray("up").getJsonObject(0).getString("href"));

        HttpResponse<String> options = send("OPTIONS", "/lset.meta", null);
        assertEquals(204, options.statusCode());
        assertTrue(options.headers().firstValue("Allow").orElse("").contains("PATCH"));

        // Metadata writes MUST be conditional.
        assertEquals(428, send("PATCH", "/lset.meta", "{\"describedby\":[{\"href\":\"https://shapes.example/S\"}]}",
                "Content-Type", "application/merge-patch+json").statusCode());
        // Wrong patch media type.
        assertEquals(415, send("PUT", "/lset.meta", "{}", "Content-Type", "application/json", "If-Match", etag)
                .statusCode());

        // Conditional JSON Merge Patch adds a user-managed link.
        HttpResponse<String> patched = send("PATCH", "/lset.meta",
                "{\"describedby\":[{\"href\":\"https://shapes.example/S\"}]}",
                "Content-Type", "application/merge-patch+json", "If-Match", etag);
        assertEquals(204, patched.statusCode());

        JsonObject after = parse(send("GET", "/lset.meta", null).body()).getJsonArray("linkset").getJsonObject(0);
        assertEquals("https://shapes.example/S",
                after.getJsonArray("describedby").getJsonObject(0).getString("href"));

        // A stale precondition is rejected.
        assertEquals(412, send("PATCH", "/lset.meta", "{\"license\":[{\"href\":\"https://x/\"}]}",
                "Content-Type", "application/merge-patch+json", "If-Match", "\"deadbeef00000000\"").statusCode());
    }

    @Test
    void deletingAResourceRemovesItsLinkset() throws Exception {
        assertEquals(201, send("PUT", "/del", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());
        assertEquals(200, send("GET", "/del.meta", null).statusCode());
        assertEquals(204, send("DELETE", "/del", null).statusCode());
        assertEquals(404, send("GET", "/del.meta", null).statusCode());
    }

    @Test
    void storageDescriptionIsLwsJsonAndAdvertisesItself() throws Exception {
        // Canonical representation is application/lws+json (default, no Accept).
        HttpResponse<String> r = send("GET", "/.lws/storage-description", null);
        assertEquals(200, r.statusCode());
        assertTrue(r.headers().firstValue("Content-Type").orElse("").startsWith("application/lws+json"));
        JsonObject doc = parse(r.body());
        assertEquals("Storage", doc.getString("type"));
        assertEquals(baseUrl + "/", doc.getString("id"));

        // The service array MUST include a StorageDescription entry pointing at this resource.
        boolean hasStorageDescription = false;
        boolean hasNotification = false;
        for (JsonValue v : doc.getJsonArray("service")) {
            JsonObject s = v.asJsonObject();
            if (s.getString("type").equals("StorageDescription")
                    && s.getString("serviceEndpoint").equals(baseUrl + "/.lws/storage-description")) {
                hasStorageDescription = true;
            }
            if (s.getString("type").equals("NotificationService")) {
                hasNotification = true;
            }
        }
        assertTrue(hasStorageDescription, "service array must contain a StorageDescription entry: " + r.body());
        assertTrue(hasNotification, r.body());

        // Content-Type is echoed across the JSON family; RDF stays available via negotiation.
        assertTrue(ct("/.lws/storage-description", "application/json").startsWith("application/json"));
        assertTrue(ct("/.lws/storage-description", "application/ld+json").startsWith("application/ld+json"));
        assertTrue(ct("/.lws/storage-description", "text/turtle").startsWith("text/turtle"));
    }

    private static String ct(String path, String accept) throws Exception {
        return send("GET", path, null, "Accept", accept).headers().firstValue("Content-Type").orElse("");
    }

    @Test
    void recursiveContainerDelete() throws Exception {
        assertEquals(201, send("PUT", "/tree/", null,
                "Link", "<https://www.w3.org/ns/lws#Container>; rel=\"type\"").statusCode());
        assertEquals(201, send("PUT", "/tree/sub/", null,
                "Link", "<https://www.w3.org/ns/lws#Container>; rel=\"type\"").statusCode());
        assertEquals(201, send("PUT", "/tree/sub/leaf", "hi", "Content-Type", "text/plain").statusCode());

        // A non-empty container without Depth is refused.
        assertEquals(409, send("DELETE", "/tree/", null).statusCode());

        // Depth: infinity removes the container and its whole subtree.
        assertEquals(204, send("DELETE", "/tree/", null, "Depth", "infinity").statusCode());
        assertEquals(404, send("GET", "/tree/", null).statusCode());
        assertEquals(404, send("GET", "/tree/sub/", null).statusCode());
        assertEquals(404, send("GET", "/tree/sub/leaf", null).statusCode());
    }

    @Test
    void ifModifiedSinceConditionalGet() throws Exception {
        assertEquals(201, send("PUT", "/ims", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());
        String lastModified = send("GET", "/ims", null).headers().firstValue("Last-Modified").orElseThrow();

        // Unchanged since its own Last-Modified -> 304.
        assertEquals(304, send("GET", "/ims", null, "If-Modified-Since", lastModified).statusCode());
        // Modified since a long-past date -> 200.
        assertEquals(200, send("GET", "/ims", null, "If-Modified-Since", "Mon, 01 Jan 1990 00:00:00 GMT").statusCode());
    }

    @Test
    void sparqlUpdateLoadAndServiceAreBlocked() throws Exception {
        assertEquals(201, send("PUT", "/su", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());
        // A local update works.
        assertEquals(204, send("PATCH", "/su", "INSERT DATA { <http://x/> <http://schema.org/name> \"y\" }",
                "Content-Type", "application/sparql-update").statusCode());
        // LOAD (SSRF) is refused.
        assertEquals(403, send("PATCH", "/su", "LOAD <http://169.254.169.254/latest/meta-data/>",
                "Content-Type", "application/sparql-update").statusCode());
        // SERVICE inside a WHERE is refused.
        assertEquals(403, send("PATCH", "/su", "INSERT { <http://x/> <http://schema.org/name> ?n } "
                + "WHERE { SERVICE <http://evil.example/sparql> { <http://x/> <http://schema.org/name> ?n } }",
                "Content-Type", "application/sparql-update").statusCode());
    }

    @Test
    void errorsUseProblemJson() throws Exception {
        HttpResponse<String> notFound = send("GET", "/no-such-resource", null);
        assertEquals(404, notFound.statusCode());
        assertTrue(notFound.headers().firstValue("Content-Type").orElse("").startsWith("application/problem+json"));
        JsonObject problem = parse(notFound.body());
        assertEquals(404, problem.getInt("status"));
        assertTrue(problem.containsKey("title"));
    }

    @Test
    void linksetJsonPatch() throws Exception {
        assertEquals(201, send("PUT", "/ljp", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());
        HttpResponse<String> meta = send("GET", "/ljp.meta", null);
        // The linkset advertises both PATCH formats.
        assertTrue(meta.headers().firstValue("Accept-Patch").orElse("").contains("json-patch+json"));
        String etag = meta.headers().firstValue("ETag").orElseThrow();

        // RFC 6902 add of a user-managed relation (conditional, like merge patch).
        assertEquals(204, send("PATCH", "/ljp.meta",
                "[{\"op\":\"add\",\"path\":\"/describedby\",\"value\":[{\"href\":\"https://shapes.example/S\"}]}]",
                "Content-Type", "application/json-patch+json", "If-Match", etag).statusCode());

        JsonObject after = parse(send("GET", "/ljp.meta", null).body()).getJsonArray("linkset").getJsonObject(0);
        assertEquals("https://shapes.example/S",
                after.getJsonArray("describedby").getJsonObject(0).getString("href"));
    }

    @Test
    void preferSetLinksetCombinedWrite() throws Exception {
        // A Link header without Prefer: set-linkset does NOT touch the linkset (off by default).
        assertEquals(201, send("PUT", "/sl0", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle",
                "Link", "<https://shapes.example/S>; rel=\"describedby\"").statusCode());
        assertFalse(parse(send("GET", "/sl0.meta", null).body())
                .getJsonArray("linkset").getJsonObject(0).containsKey("describedby"),
                "Link headers must be ignored without Prefer: set-linkset");

        // PUT content + Prefer: set-linkset replaces the linkset from the Link headers.
        HttpResponse<String> put = send("PUT", "/sl", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle", "Prefer", "set-linkset",
                "Link", "<https://shapes.example/S>; rel=\"describedby\"");
        assertEquals(201, put.statusCode());
        assertEquals("set-linkset", put.headers().firstValue("Preference-Applied").orElse(""));
        JsonObject m = parse(send("GET", "/sl.meta", null).body()).getJsonArray("linkset").getJsonObject(0);
        assertEquals("https://shapes.example/S", m.getJsonArray("describedby").getJsonObject(0).getString("href"));

        // PATCH content + Prefer: set-linkset merges another relation, keeping describedby.
        assertEquals(204, send("PATCH", "/sl", "INSERT DATA { <http://ex/s> <http://schema.org/x> \"y\" }",
                "Content-Type", "application/sparql-update", "Prefer", "set-linkset",
                "Link", "<https://example/lic>; rel=\"license\"").statusCode());
        JsonObject after = parse(send("GET", "/sl.meta", null).body()).getJsonArray("linkset").getJsonObject(0);
        assertEquals("https://shapes.example/S", after.getJsonArray("describedby").getJsonObject(0).getString("href"));
        assertEquals("https://example/lic", after.getJsonArray("license").getJsonObject(0).getString("href"));
    }

    @Test
    void preferLinkRelationsFiltersLinksetRead() throws Exception {
        assertEquals(201, send("PUT", "/plr", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());
        String etag = send("GET", "/plr.meta", null).headers().firstValue("ETag").orElseThrow();
        assertEquals(204, send("PATCH", "/plr.meta", "{\"describedby\":[{\"href\":\"https://shapes.example/S\"}]}",
                "Content-Type", "application/merge-patch+json", "If-Match", etag).statusCode());

        // include="up" -> only the anchor and the up relation are returned.
        HttpResponse<String> inc = send("GET", "/plr.meta", null, "Prefer", "include=\"up\"");
        assertEquals("include", inc.headers().firstValue("Preference-Applied").orElse(""));
        JsonObject m = parse(inc.body()).getJsonArray("linkset").getJsonObject(0);
        assertTrue(m.containsKey("anchor") && m.containsKey("up"));
        assertFalse(m.containsKey("describedby"));
        assertFalse(m.containsKey("type"));

        // omit="describedby" -> that relation is dropped, the rest retained.
        HttpResponse<String> om = send("GET", "/plr.meta", null, "Prefer", "omit=\"describedby\"");
        assertEquals("omit", om.headers().firstValue("Preference-Applied").orElse(""));
        JsonObject m2 = parse(om.body()).getJsonArray("linkset").getJsonObject(0);
        assertFalse(m2.containsKey("describedby"));
        assertTrue(m2.containsKey("type"));
    }

    @Test
    void literalMetadataRoundTrips() throws Exception {
        assertEquals(201, send("PUT", "/lit", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());
        String etag = send("GET", "/lit.meta", null).headers().firstValue("ETag").orElseThrow();
        // Literal title (string) + creator (string array) + an RFC 9264 title attribute on a target.
        assertEquals(204, send("PATCH", "/lit.meta",
                "{\"title\":\"My Document\",\"creator\":[\"Alice\",\"Bob\"],"
                        + "\"describedby\":[{\"href\":\"https://shapes.example/S\",\"title\":\"Schema\"}]}",
                "Content-Type", "application/merge-patch+json", "If-Match", etag).statusCode());
        JsonObject m = parse(send("GET", "/lit.meta", null).body()).getJsonArray("linkset").getJsonObject(0);
        assertEquals("My Document", m.getString("title"));
        assertEquals("Alice", m.getJsonArray("creator").getString(0));
        assertEquals("Schema", m.getJsonArray("describedby").getJsonObject(0).getString("title"));
    }

    @Test
    void rfc9530DigestFields() throws Exception {
        String body = "<#it> <http://schema.org/name> \"d\" .";
        // A correct inbound Content-Digest is accepted; a wrong one is refused before any write.
        HttpResponse<String> created = send("PUT", "/dig", body, "Content-Type", "text/turtle",
                "Content-Digest", contentDigest(body));
        assertEquals(201, created.statusCode());
        // The write response advertises that integrity-protected writes are accepted (RFC 9530 §4).
        assertTrue(created.headers().firstValue("Want-Content-Digest").orElse("").contains("sha-256"),
                created.headers().map().toString());
        // OPTIONS advertises the same.
        assertTrue(send("OPTIONS", "/dig", null).headers().firstValue("Want-Content-Digest")
                .orElse("").contains("sha-512"));
        assertEquals(400, send("PUT", "/dig2", body, "Content-Type", "text/turtle",
                "Content-Digest", contentDigest("a different body")).statusCode());
        assertEquals(404, send("GET", "/dig2", null).statusCode()); // the rejected write created nothing

        // A read honours Want-Repr-Digest and the digest matches the representation actually sent.
        HttpResponse<String> rdf = send("GET", "/dig", null, "Accept", "text/turtle", "Want-Repr-Digest", "sha-256=1");
        assertEquals(contentDigest(rdf.body()), rdf.headers().firstValue("Repr-Digest").orElse(""));

        // Binary Repr-Digest is served from the persisted content hash (sha-512 unavailable -> sha-256).
        assertEquals(201, send("PUT", "/dig.bin", "PAYLOAD", "Content-Type", "application/octet-stream").statusCode());
        HttpResponse<String> bin = send("GET", "/dig.bin", null, "Want-Repr-Digest", "sha-512=2, sha-256=1");
        assertEquals(contentDigest("PAYLOAD"), bin.headers().firstValue("Repr-Digest").orElse(""));
    }

    /** The RFC 9530 {@code sha-256} Content-Digest value of a UTF-8 string. */
    private static String contentDigest(String body) throws Exception {
        byte[] d = java.security.MessageDigest.getInstance("SHA-256")
                .digest(body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return "sha-256=:" + java.util.Base64.getEncoder().encodeToString(d) + ":";
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

    private static JsonObject parse(String json) {
        return Json.createReader(new StringReader(json)).readObject();
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
