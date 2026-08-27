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
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 * Conformance tests for the lws10-core operations and processes that are HTTP-observable: the
 * lws+json container representation and its content negotiation, byte-range requests, conditional
 * PUT (428/412), the metadata Link relations (rel="up"/"linkset"), the linkset metadata resource
 * (read, OPTIONS, conditional PATCH/PUT), linkset removal on delete, and RFC 9457 problem+json.
 *
 * <p><strong>Why this is abstract (finding M47).</strong> These assertions used to run in exactly
 * one posture: {@code lws.dev.open=true}, with no {@code Authorization} header on any request. That
 * is the posture in which {@code DefaultAccessPolicy} short-circuits every read and every write, so
 * four hundred lines of protocol conformance were pinned only for a deployment nobody runs. The
 * suite therefore could not have caught a regression that made the protocol behave differently once
 * an owner was configured — a conditional PUT answered {@code 403} instead of {@code 412}, an
 * absent resource masked as {@code 401} instead of {@code 404}, a container listing silently
 * filtered down to nothing. Each of those is an authorization change that presents as a protocol
 * bug, and the open-mode run is blind to all of them.
 *
 * <p>So the tests live here, unchanged, and two thin subclasses run them: one in open mode
 * ({@link OperationsConformanceTest}, the historical posture) and one with a configured owner
 * presenting a real credential ({@link OperationsConformanceOwnerTest}). Subclasses differ only in
 * {@link #configure(Properties)} and {@link #authorizationToken()}; every expected status code is
 * shared, which is the claim being made — the protocol is the same protocol either way.
 *
 * <p><strong>Why the lifecycle is {@code PER_CLASS}.</strong> The server is booted in
 * {@code @BeforeAll}, and the posture is what the boot depends on, so {@code @BeforeAll} has to be
 * able to call an overridable method. That requires it to be non-static, which requires this
 * lifecycle. It also gives each subclass its own {@code server} / {@code components} /
 * {@code baseUrl} / {@code tempDir} rather than one copy shared on the base class — the two servers
 * run against two TDB2 datasets, and a TDB2 lock is per-directory.
 *
 * @author Erich Bremer
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class AbstractOperationsConformance {

    /**
     * This subclass's data directory. Deleted on the way out where the platform allows it, and by
     * the next run's sweep where it does not — see {@link TestDirs}. It used to be a bare
     * {@code createTempDirectory} that nothing ever removed, and the leak once filled a disk.
     *
     * <p>One per test instance, and with {@code PER_CLASS} that is one per concrete subclass. Two
     * {@code LwsComponents} must never share a directory: the TDB2 lock is held per-directory.
     */
    private final Path tempDir = TestDirs.create();

    private Server server;
    private LwsComponents components;
    private String baseUrl;
    private HttpClient http;

    /**
     * Declare the authorization posture of this run. {@code lws.base-uri} and {@code lws.data-dir}
     * are already set on {@code p}; the base URI is passed through rather than kept private because
     * a credential minted for this storage has to name it as its audience.
     */
    protected abstract void configure(Properties p);

    /**
     * The Bearer credential every request in this run carries, or {@code null} to run anonymously.
     * Read once per request, after {@link #configure(Properties)} has run.
     */
    protected String authorizationToken() {
        return null;
    }

    @BeforeAll
    void start() throws Exception {
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.data-dir", tempDir.toString());
        configure(p);
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    void stop() throws Exception {
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
        String etag = send("GET", "/del.meta", null).headers().firstValue("ETag").orElseThrow();
        assertEquals(204, send("PATCH", "/del.meta", "{\"describedby\":[{\"href\":\"https://shapes.example/S\"}]}",
                "Content-Type", "application/merge-patch+json", "If-Match", etag).statusCode());
        assertEquals(200, send("GET", "/del.meta", null).statusCode());

        assertEquals(204, send("DELETE", "/del", null).statusCode());
        assertEquals(404, send("GET", "/del.meta", null).statusCode());

        // A resource created at the same path must not inherit the dead one's metadata: the linkset
        // is erased in the transaction that deletes the resource, not by a listener afterwards that
        // could fail and only log (finding H24).
        assertEquals(201, send("PUT", "/del", "<#it> <http://schema.org/name> \"y\" .",
                "Content-Type", "text/turtle").statusCode());
        JsonObject reborn = parse(send("GET", "/del.meta", null).body()).getJsonArray("linkset").getJsonObject(0);
        assertFalse(reborn.containsKey("describedby"), "a re-created path must not resurrect the old linkset");
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

    private String ct(String path, String accept) throws Exception {
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

        // What the server SENDS must be an IMF-fixdate — a two-digit day, which
        // DateTimeFormatter.RFC_1123_DATE_TIME does not produce (RFC 9110 §5.6.7).
        assertTrue(lastModified.matches("\\w{3}, \\d{2} \\w{3} \\d{4} \\d{2}:\\d{2}:\\d{2} GMT"),
                "Last-Modified must be an IMF-fixdate: " + lastModified);

        // ...and what it ACCEPTS is wider, which is a separate requirement in the same section and
        // was briefly broken by fixing the sender. The unpadded day is the sharp case: it is exactly
        // what this server itself emitted before the sender was corrected, so a client echoing a
        // validator it cached then would silently have lost conditional GET — an unparseable
        // If-Modified-Since is treated as absent, so the answer is a full 200.
        String unpadded = lastModified.replaceFirst(", 0(\\d) ", ", $1 ");
        if (!unpadded.equals(lastModified)) {
            assertEquals(304, send("GET", "/ims", null, "If-Modified-Since", unpadded).statusCode(),
                    "an unpadded day must still be understood: " + unpadded);
        }
        assertEquals(304, send("GET", "/ims", null, "If-Modified-Since",
                lastModified.toUpperCase(java.util.Locale.ROOT)).statusCode(),
                "the date is case-insensitive");
        assertEquals(304, send("GET", "/ims", null, "If-Modified-Since",
                lastModified.replace("GMT", "+0000")).statusCode(),
                "a numeric offset must still be understood");
    }

    @Test
    void sparqlUpdateLoadAndServiceAreBlocked() throws Exception {
        assertEquals(201, send("PUT", "/su", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());
        // A local update works. PATCH names the version it changes, as PUT does (prior-review 14).
        assertEquals(204, send("PATCH", "/su", "INSERT DATA { <http://x/> <http://schema.org/name> \"y\" }",
                "Content-Type", "application/sparql-update", "If-Match", etagOf("/su")).statusCode());
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
                "If-Match", etagOf("/sl"),
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

    // ----- M21: an entity-tag names a representation, not just a resource -----

    /**
     * The five RDF serializations of one resource carry five different entity-tags, and a tag from
     * one of them does not revalidate another (RFC 9110 §8.8.1).
     *
     * <p>Against the pre-fix code all five are {@code meta.etag()}, so the first assertion fails and
     * — more damagingly — a client that had cached the Turtle and asked for JSON-LD was answered
     * {@code 304} and went on using the Turtle.
     */
    @Test
    void eachSerializationHasItsOwnEntityTag() throws Exception {
        assertEquals(201, send("PUT", "/m21", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());

        String turtle = etagOf("/m21", "text/turtle");
        String jsonld = etagOf("/m21", "application/ld+json");
        String ntriples = etagOf("/m21", "application/n-triples");
        assertEquals(3, new java.util.HashSet<>(java.util.List.of(turtle, jsonld, ntriples)).size(),
                "three serializations, three tags: " + turtle + " " + jsonld + " " + ntriples);

        // The tag from one representation must not 304 a request for another.
        assertEquals(200, send("GET", "/m21", null, "Accept", "application/ld+json",
                "If-None-Match", turtle).statusCode(),
                "a Turtle validator must not satisfy a JSON-LD request");
        // Its own does.
        assertEquals(304, send("GET", "/m21", null, "Accept", "text/turtle",
                "If-None-Match", turtle).statusCode());
    }

    /**
     * A {@code 304} carries the headers a {@code 200} would have carried for the same request —
     * above all {@code Vary}, without which a shared cache cannot tell the stored variant apart
     * (RFC 9110 §15.4.5).
     *
     * <p>Pre-fix this fails: {@code Vary: Accept} and {@code Accept-Patch} were set two lines
     * <em>after</em> the {@code 304} returned.
     */
    @Test
    void notModifiedStillCarriesVaryAndAcceptPatch() throws Exception {
        assertEquals(201, send("PUT", "/m21v", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());
        String tag = etagOf("/m21v", "text/turtle");
        HttpResponse<String> notModified =
                send("GET", "/m21v", null, "Accept", "text/turtle", "If-None-Match", tag);
        assertEquals(304, notModified.statusCode());
        assertEquals("Accept", notModified.headers().firstValue("Vary").orElse(""));
        assertTrue(notModified.headers().firstValue("Accept-Patch").isPresent());
        assertTrue(notModified.headers().firstValue("ETag").isPresent());
    }

    /**
     * A conditional write may be conditioned on the tag from <em>any</em> representation, because
     * they all name one resource state. This is what stops the per-representation tags from breaking
     * optimistic concurrency: a client that reads JSON-LD and writes Turtle holds a JSON-LD tag.
     *
     * <p>A guard, not a discriminator: it passes pre-fix too, because pre-fix there was only one tag.
     * It is here because it is the assertion that would have failed had {@code If-Match} been left
     * comparing exactly — which is the obvious way to implement per-representation tags and the way
     * that silently breaks every conditional write in the server.
     */
    @Test
    void aTagFromAnyRepresentationConditionsAWrite() throws Exception {
        assertEquals(201, send("PUT", "/m21w", "<#it> <http://schema.org/name> \"x\" .",
                "Content-Type", "text/turtle").statusCode());
        String jsonld = etagOf("/m21w", "application/ld+json");
        assertEquals(204, send("PUT", "/m21w", "<#it> <http://schema.org/name> \"y\" .",
                "Content-Type", "text/turtle", "If-Match", jsonld).statusCode());
        // And a tag for a state that has moved on is still refused.
        assertEquals(412, send("PUT", "/m21w", "<#it> <http://schema.org/name> \"z\" .",
                "Content-Type", "text/turtle", "If-Match", jsonld).statusCode());
    }

    // ----- M22 / conformance: the storage description is one document with two renderings -----

    /**
     * The storage description's entity-tag is stable, so a conditional {@code GET} on discovery can
     * return {@code 304}.
     *
     * <p>Pre-fix it was {@code Etags.forModel} over a model containing fresh blank nodes, so it
     * differed on every call: two successive GETs returned different tags and no revalidation could
     * ever match.
     */
    @Test
    void discoveryIsConditionallyCacheable() throws Exception {
        String first = send("GET", "/.lws/storage-description", null).headers()
                .firstValue("ETag").orElseThrow();
        String second = send("GET", "/.lws/storage-description", null).headers()
                .firstValue("ETag").orElseThrow();
        assertEquals(first, second, "the description cannot change while the process lives");
        assertEquals(304, send("GET", "/.lws/storage-description", null, "If-None-Match", first).statusCode());
        // The RDF rendering is a different representation, so a different tag — and the JSON tag
        // must not revalidate it.
        String turtle = send("GET", "/.lws/storage-description", null, "Accept", "text/turtle")
                .headers().firstValue("ETag").orElseThrow();
        assertFalse(first.equals(turtle), "one tag per representation");
        assertEquals(200, send("GET", "/.lws/storage-description", null,
                "Accept", "text/turtle", "If-None-Match", first).statusCode());
    }

    /**
     * Both renderings describe the same graph. The RDF one used to emit a capability node carrying
     * only its {@code rdf:type}, silently dropping the {@code PatchSupport} media-type map, the
     * negotiable serializations and the digest algorithms — so a client that negotiated Turtle was
     * told materially less than one that took the default.
     */
    @Test
    void bothRenderingsOfTheDescriptionCarryTheSameFacts() throws Exception {
        String turtle = send("GET", "/.lws/storage-description", null, "Accept", "text/turtle").body();
        assertTrue(turtle.contains("sha-256"), "digest algorithms reach the RDF rendering: " + turtle);
        assertTrue(turtle.contains("application/sparql-update"), "PatchSupport detail does too");
        assertTrue(turtle.contains("StorageDescription"), "and the description resource is typed");

        JsonObject doc = parse(send("GET", "/.lws/storage-description", null).body());
        JsonObject description = doc.getJsonObject("storageDescription");
        assertEquals(baseUrl + "/.lws/storage-description", description.getString("id"));
        assertEquals("StorageDescription", description.getString("type"));
        assertEquals(baseUrl + "/", description.getString("storage"));
    }

    /**
     * Every authentication suite this deployment can actually accept is advertised. Only OpenID used
     * to be, though all four are implemented — and a client reads this document to decide what to
     * present.
     */
    @Test
    void everyUsableAuthenticationSuiteIsAdvertised() throws Exception {
        JsonObject doc = parse(send("GET", "/.lws/storage-description", null).body());
        java.util.Set<String> types = new java.util.HashSet<>();
        for (JsonValue v : doc.getJsonArray("capability")) {
            types.add(v.asJsonObject().getString("type", ""));
        }
        assertTrue(types.contains("https://w3c.github.io/lws-protocol/lws10-authn-openid/"), types.toString());
        assertTrue(types.contains("https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/"), types.toString());
        assertTrue(types.contains("https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/"), types.toString());
        // SAML is inert until an IdP certificate is configured, and this server has none, so it is
        // the one suite that must NOT be advertised here.
        assertFalse(types.contains("https://w3c.github.io/lws-protocol/lws10-authn-saml/"),
                "an unconfigured suite must not be advertised: " + types);
    }

    // ----- conformance: POST to a data resource is 405, not 409 -----

    /**
     * A data resource does not support {@code POST}, which is what {@code 405} says. {@code 409}
     * says the request conflicts with the target's current state — retry when it changes — and no
     * state change makes {@code POST} work on a data resource.
     */
    @Test
    void postingToADataResourceIsMethodNotAllowed() throws Exception {
        assertEquals(201, send("PUT", "/notacontainer", "x", "Content-Type", "text/plain").statusCode());
        HttpResponse<String> r = send("POST", "/notacontainer", "y", "Content-Type", "text/plain");
        assertEquals(405, r.statusCode());
        String allow = r.headers().firstValue("Allow").orElse("");
        assertFalse(allow.contains("POST"), "Allow must not offer the method just refused: " + allow);
        assertTrue(allow.contains("PUT"), allow);
    }

    // ----- conformance: a type search needs a type clause -----

    /** {@code GET /.lws/type-search} with no type clause used to enumerate the whole storage. */
    @Test
    void typeSearchRequiresATypeClause() throws Exception {
        assertEquals(400, send("GET", "/.lws/type-search", null).statusCode());
        assertEquals(400, send("GET", "/.lws/type-search?describedby="
                + java.net.URLEncoder.encode("https://shapes.example/S", java.nio.charset.StandardCharsets.UTF_8),
                null).statusCode(), "a relation-only filter is still not a type search");
        assertEquals(200, send("GET", "/.lws/type-search?type="
                + java.net.URLEncoder.encode("https://www.w3.org/ns/lws#DataResource",
                        java.nio.charset.StandardCharsets.UTF_8), null).statusCode());
    }

    // ----- L28: If-None-Match on writes, and PATCH aligned with PUT -----

    /**
     * {@code If-None-Match: *} is create-only {@code PUT}: it succeeds when nothing is there and is
     * refused {@code 412} when something is.
     *
     * <p>Pre-fix the header was never read on a write at all, so the second PUT here replaced the
     * resource and answered {@code 204} — the client asked to create a resource and silently
     * overwrote somebody's.
     */
    @Test
    void ifNoneMatchStarMakesPutCreateOnly() throws Exception {
        assertEquals(201, send("PUT", "/l28-new", "first", "Content-Type", "text/plain",
                "If-None-Match", "*").statusCode(), "nothing is there, so it is created");
        assertEquals(412, send("PUT", "/l28-new", "second", "Content-Type", "text/plain",
                "If-None-Match", "*").statusCode(), "something is there now, so it is refused");
        assertEquals("first", send("GET", "/l28-new", null).body(), "and the original survived");
    }

    /**
     * A create-only PUT is a conditional request, so it must not be answered {@code 428} for want of
     * an {@code If-Match} naming a version the client is asserting does not exist. A tag
     * <em>list</em> is not the same thing: it names no version of this resource, so accepting it
     * would turn one junk header into the unconditional overwrite the rule exists to refuse.
     */
    @Test
    void onlyTheStarFormRelaxesTheMandatoryPrecondition() throws Exception {
        assertEquals(201, send("PUT", "/l28-star", "v1", "Content-Type", "text/plain").statusCode());
        assertEquals(412, send("PUT", "/l28-star", "v2", "Content-Type", "text/plain",
                "If-None-Match", "*").statusCode(), "412, not 428: it is a conditional request");
        assertEquals(428, send("PUT", "/l28-star", "v2", "Content-Type", "text/plain",
                "If-None-Match", "\"not-a-real-tag\"").statusCode(),
                "a tag list names no version of this resource and must not stand in for If-Match");
        assertEquals("v1", send("GET", "/l28-star", null).body());
    }

    /**
     * {@code PATCH} names the version it changes, exactly as {@code PUT} does (prior-review finding
     * 14). It was the one read-modify-write method that accepted an unconditional request, so two
     * clients could patch from the same starting state and the second silently discarded the first.
     */
    @Test
    void patchingAnExistingResourceIsConditional() throws Exception {
        assertEquals(201, send("PUT", "/l28-patch", "{\"a\":1}", "Content-Type", "application/json")
                .statusCode());
        assertEquals(428, send("PATCH", "/l28-patch", "{\"b\":2}",
                "Content-Type", "application/merge-patch+json").statusCode());
        String etag = etagOf("/l28-patch");
        assertEquals(412, send("PATCH", "/l28-patch", "{\"b\":2}",
                "Content-Type", "application/merge-patch+json",
                "If-Match", "\"deadbeef00000000\"").statusCode());
        assertEquals(204, send("PATCH", "/l28-patch", "{\"b\":2}",
                "Content-Type", "application/merge-patch+json", "If-Match", etag).statusCode());
        assertTrue(send("GET", "/l28-patch", null).body().contains("\"b\":2"));
    }

    /**
     * {@code DELETE} stays optionally conditional, deliberately. It is not an update, it does not
     * depend on having read a version, and RFC 9110 asks for no precondition on it — requiring one
     * would break every ordinary cleanup without closing a lost update, because there is no lost
     * state after a delete.
     */
    @Test
    void deleteRemainsUnconditional() throws Exception {
        assertEquals(201, send("PUT", "/l28-del", "x", "Content-Type", "text/plain").statusCode());
        assertEquals(204, send("DELETE", "/l28-del", null).statusCode());
    }

    /** The current entity-tag of a resource, for a conditional write. */
    private String etagOf(String path) throws Exception {
        return send("GET", path, null).headers().firstValue("ETag").orElseThrow();
    }

    /** The unquoted entity-tag a GET of {@code path} returns for the named media type. */
    private String etagOf(String path, String accept) throws Exception {
        return send("GET", path, null, "Accept", accept).headers().firstValue("ETag").orElseThrow();
    }

    private HttpResponse<String> send(String method, String path, String body, String... headers)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path));
        String token = authorizationToken();
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
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
