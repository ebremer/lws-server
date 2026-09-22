package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * End-to-end integration tests: boots the real bare-Jetty stack ({@link JettyLauncher#buildHandler}
 * over a live {@link LwsComponents}) on a free port and drives it with an HTTP client, exercising
 * the full request → filter → servlet → service → store path. Runs in open mode so CRUD needs no
 * credentials.
 *
 * @author Erich Bremer
 */
class EndToEndTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}. It used to be a bare
     * {@code createTempDirectory} that nothing ever removed, and the leak once filled a disk.
     */
    private static final Path tempDir = TestDirs.create();

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        Path dataDir = tempDir;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://localhost:" + port);
        // Open mode: this class asserts protocol behaviour, not authorization outcomes,
        // so it opts in to the development posture rather than configuring an owner.
        p.setProperty("lws.dev.open", "true");
        p.setProperty("lws.data-dir", dataDir.toString());
        p.setProperty("lws.webhook.max-attempts", "1");           // fail webhook delivery fast
        p.setProperty("lws.subscription.purge-interval-seconds", "0"); // no background purge during the test
        p.setProperty("lws.webhook.allowed-hosts", "localhost");  // the test inbox is on loopback
        p.setProperty("lws.max-request-bytes", "4096");           // small, so the 413 path is testable
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        baseUrl = "http://localhost:" + port;
        http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
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
    void servesStorageRootDescriptionAndJwks() throws Exception {
        HttpResponse<String> root = send("GET", "/", null, null, "Accept", "text/turtle");
        assertEquals(200, root.statusCode());
        assertTrue(root.headers().firstValue("Content-Type").orElse("").startsWith("text/turtle"));
        assertTrue(root.body().contains("Container"), "root should be an lws:Container");
        List<String> links = root.headers().allValues("Link");
        assertTrue(links.stream().anyMatch(l -> l.contains("rel=\"type\"")), "type Link header");
        assertTrue(links.stream().anyMatch(l -> l.contains("<" + baseUrl + "/>; rel=\"https://www.w3.org/ns/lws#storage\"")),
                "the link to the storage: " + links);

        assertTrue(send("GET", "/.lws/storage-description", null, null, "Accept", "text/turtle")
                .body().contains("NotificationService"));

        HttpResponse<String> jwks = send("GET", "/.lws/jwks", null, null);
        assertEquals(200, jwks.statusCode());
        assertTrue(jwks.body().contains("\"keys\""));
    }

    @Test
    void rdfResourceCreateNegotiateReplaceDelete() throws Exception {
        HttpResponse<String> created = send("POST", "/", "text/turtle",
                "<#it> <http://schema.org/name> \"Hi\" .", "Slug", "greeting");
        assertEquals(201, created.statusCode());
        String location = created.headers().firstValue("Location").orElse(null);
        assertEquals(baseUrl + "/greeting", location);

        assertTrue(send("GET", "/greeting", null, null, "Accept", "text/turtle").body().contains("Hi"));

        HttpResponse<String> jsonLd = send("GET", "/greeting", null, null, "Accept", "application/ld+json");
        assertEquals(200, jsonLd.statusCode());
        assertTrue(jsonLd.headers().firstValue("Content-Type").orElse("").startsWith("application/ld+json"));
        assertTrue(jsonLd.body().contains("schema.org/name"));

        // Replacing an existing resource MUST be conditional (lws10-core): unconditional PUT -> 428.
        assertEquals(428, send("PUT", "/greeting", "text/turtle",
                "<#it> <http://schema.org/name> \"Bye\" .").statusCode());
        assertEquals(204, send("PUT", "/greeting", "text/turtle",
                "<#it> <http://schema.org/name> \"Bye\" .", "If-Match", "*").statusCode());
        assertTrue(send("GET", "/greeting", null, null, "Accept", "text/turtle").body().contains("Bye"));

        assertEquals(204, send("DELETE", "/greeting", null, null).statusCode());
        assertEquals(404, send("GET", "/greeting", null, null).statusCode());
    }

    @Test
    void containerCreatePatchAndDeleteGuards() throws Exception {
        assertEquals(201, send("PUT", "/box/", null, null,
                "Link", "<http://www.w3.org/ns/ldp#Container>; rel=\"type\"").statusCode());
        assertEquals(201, send("PUT", "/box/item", "text/turtle",
                "<#x> <http://schema.org/name> \"thing\" .").statusCode());

        assertTrue(send("GET", "/box/", null, null, "Accept", "text/turtle").body().contains("/box/item"));

        // PATCH names the version it changes, as PUT does (prior-review finding 14): a patch is a
        // read-modify-write against a version the client has already read, and it was the one such
        // method that accepted an unconditional request.
        assertEquals(204, send("PATCH", "/box/item", "application/sparql-update",
                "INSERT DATA { <" + baseUrl + "/box/item#x> <http://schema.org/age> 42 }",
                "If-Match", etagOf("/box/item")).statusCode());
        assertTrue(send("GET", "/box/item", null, null, "Accept", "text/turtle").body().contains("42"));

        assertEquals(409, send("DELETE", "/box/", null, null).statusCode(), "non-empty container");
        assertEquals(204, send("DELETE", "/box/item", null, null).statusCode());
        assertEquals(204, send("DELETE", "/box/", null, null).statusCode());
    }

    @Test
    void binaryUploadAndDownloadRoundTrip() throws Exception {
        HttpResponse<String> created = send("POST", "/", "image/png", "PNGBYTES", "Slug", "pic");
        assertEquals(201, created.statusCode());
        HttpResponse<String> got = send("GET", "/pic", null, null);
        assertEquals(200, got.statusCode());
        assertEquals("image/png", got.headers().firstValue("Content-Type").orElse(""));
        assertEquals("PNGBYTES", got.body());
    }

    @Test
    void conditionalOptionsAndErrors() throws Exception {
        assertEquals(304, send("GET", "/", null, null, "If-None-Match", "*").statusCode());

        HttpResponse<String> options = send("OPTIONS", "/", null, null);
        assertEquals(204, options.statusCode());
        assertTrue(options.headers().firstValue("Allow").orElse("").contains("POST"));

        assertEquals(404, send("GET", "/does-not-exist", null, null).statusCode());
        assertEquals(403, send("DELETE", "/", null, null).statusCode(), "cannot delete the root");
        HttpResponse<String> unauth = send("GET", "/", null, null, "Authorization", "Bearer not.a.jwt");
        assertEquals(401, unauth.statusCode());
        // A 401 links to the storage, whose URI dereferences to the storage description, so the
        // client can discover how to authenticate (lws10-core).
        assertTrue(unauth.headers().allValues("Link").stream()
                        .anyMatch(l -> l.contains("rel=\"https://www.w3.org/ns/lws#storage\"")),
                "401 should link to the storage");
    }

    @Test
    void subscriptionLifecycle() throws Exception {
        String json = "{ \"type\":\"WebhookSubscription\", \"topic\":[\"" + baseUrl + "/\"],"
                + " \"inbox\":\"http://localhost:1/inbox\" }";
        // Subscription creation requires an authenticated subscriber: an anonymous one could not be
        // held to a quota, could not manage what it created, and could aim deliveries anywhere.
        assertEquals(401, send("POST", "/.lws/subscriptions", "application/ld+json", json).statusCode(),
                "anonymous subscription creation is refused by default");

        String token = DidKeyTool.mint(null, 3600, baseUrl).token();
        // The request is application/lws+json (lws10-core, Subscriptions).
        HttpResponse<String> created = send("POST", "/.lws/subscriptions", "application/lws+json", json,
                "Authorization", "Bearer " + token);
        assertEquals(201, created.statusCode());
        String location = created.headers().firstValue("Location").orElse(null);
        assertNotNull(location);
        // ...and so is the response, carrying the subscription type, its URL and the expiry the
        // server applied (lws10-notifications-webhook).
        assertTrue(created.headers().firstValue("Content-Type").orElse("").startsWith("application/lws+json"));
        jakarta.json.JsonObject response = jakarta.json.Json.createReader(
                new java.io.StringReader(created.body())).readObject();
        assertEquals("WebhookSubscription", response.getString("type"));
        assertEquals(location, response.getString("subscription"));
        assertTrue(response.containsKey("expires"), created.body());

        String auth = "Bearer " + token;
        // The endpoint lists subscriptions as an LWS container, by default in JSON.
        jakarta.json.JsonObject listing = jakarta.json.Json.createReader(new java.io.StringReader(
                send("GET", "/.lws/subscriptions", null, null, "Authorization", auth).body())).readObject();
        assertEquals("Container", listing.getString("type"));
        assertEquals(1, listing.getInt("totalItems"));
        jakarta.json.JsonObject member = listing.getJsonArray("items").getJsonObject(0);
        assertEquals(location, member.getString("id"));
        assertEquals("[\"DataResource\",\"WebhookSubscription\"]", member.getJsonArray("type").toString());
        // The collection lists only the caller's own subscriptions, and an individual subscription
        // is readable and deletable only by its subscriber (or a storage controller).
        assertTrue(send("GET", "/.lws/subscriptions", null, null,
                "Accept", "text/turtle", "Authorization", auth).body().contains(location));
        HttpResponse<String> one = send("GET", path(location), null, null,
                "Accept", "text/turtle", "Authorization", auth);
        assertEquals(200, one.statusCode());
        // Delivery bookkeeping is withheld: failureCount would report whether an arbitrary
        // client-chosen inbox URL answered, making delivery a readable probe of our network.
        assertFalse(one.body().contains("failureCount"),
                "the subscription representation must not expose delivery failure counts");

        assertEquals(204, send("DELETE", path(location), null, null, "Authorization", auth).statusCode());
    }

    /**
     * Uploaded content is read back by other users on the storage's own origin — the same origin
     * that serves the session-authenticated console — so active content must not simply render.
     */
    @Test
    void uploadedActiveContentIsNeutralisedOnRead() throws Exception {
        assertEquals(201, send("POST", "/", "text/html",
                "<script>alert(1)</script>", "Slug", "pwn.html").statusCode());

        HttpResponse<String> got = send("GET", "/pwn.html", null, null);
        assertEquals(200, got.statusCode());
        assertEquals("nosniff", got.headers().firstValue("X-Content-Type-Options").orElse(""));
        assertTrue(got.headers().firstValue("Content-Security-Policy").orElse("").contains("sandbox"),
                "a sandbox CSP should neuter it even if a client renders it");
        assertTrue(got.headers().firstValue("Content-Disposition").orElse("").startsWith("attachment"),
                "html must be sent as a download, not rendered inline");

        // An inert type keeps rendering normally, but still gets the sniffing guard.
        assertEquals(201, send("POST", "/", "image/png", "PNGDATA", "Slug", "ok.png").statusCode());
        HttpResponse<String> png = send("GET", "/ok.png", null, null);
        assertEquals("nosniff", png.headers().firstValue("X-Content-Type-Options").orElse(""));
        assertTrue(png.headers().firstValue("Content-Disposition").isEmpty(),
                "an inert media type is not forced to download");
    }

    /**
     * A client-supplied JSON-LD body chooses its own {@code @context}; dereferencing it would let
     * any writer aim the server's outbound requests at an address of their choosing.
     */
    @Test
    void remoteJsonLdContextIsNotDereferenced() throws Exception {
        String body = "{\"@context\":\"http://169.254.169.254/latest/meta-data/\","
                + "\"@id\":\"http://example.org/thing\",\"http://schema.org/name\":\"x\"}";
        HttpResponse<String> r = send("POST", "/", "application/ld+json", body, "Slug", "ctx");
        assertEquals(400, r.statusCode(),
                "a remote @context must be refused, not fetched");
    }

    /**
     * The body is buffered whole before the write is authorized, so an unbounded read is reachable
     * by an unauthenticated client. It must be refused on size, not on identity.
     */
    @Test
    void oversizedRequestBodyIsRefused() throws Exception {
        String tooBig = "x".repeat(5000); // over lws.max-request-bytes (4096)
        assertEquals(413, send("POST", "/", "text/plain", tooBig, "Slug", "big").statusCode());
        assertEquals(413, send("PUT", "/big2", "text/plain", tooBig).statusCode());
        assertFalse(send("GET", "/", null, null, "Accept", "text/turtle").body().contains("/big2"),
                "an over-sized write must not have been applied");

        // Just under the limit still works.
        assertEquals(201, send("POST", "/", "text/plain", "y".repeat(1000), "Slug", "ok-size").statusCode());
    }

    /**
     * A container's entity-tag must be the one its own preconditions are evaluated against, and it
     * must move when its membership changes — otherwise conditional writes on containers are
     * impossible (428 without a tag, 412 with the tag the server just issued).
     */
    @Test
    void containerEtagTracksMembershipAndSatisfiesIfMatch() throws Exception {
        assertEquals(201, send("PUT", "/etagbox/", null, null,
                "Link", "<http://www.w3.org/ns/ldp#Container>; rel=\"type\"").statusCode());
        String before = send("GET", "/etagbox/", null, null).headers().firstValue("ETag").orElseThrow();

        assertEquals(201, send("POST", "/etagbox/", "text/turtle",
                "<#a> <http://schema.org/name> \"a\" .", "Slug", "child").statusCode());
        String after = send("GET", "/etagbox/", null, null).headers().firstValue("ETag").orElseThrow();
        assertFalse(before.equals(after), "adding a member must change the container's ETag");

        // A stale tag is refused, and the tag the server just served is accepted.
        assertEquals(204, send("DELETE", "/etagbox/child", null, null).statusCode());
        String current = send("GET", "/etagbox/", null, null).headers().firstValue("ETag").orElseThrow();
        assertEquals(412, send("DELETE", "/etagbox/", null, null, "If-Match", before).statusCode());
        assertEquals(204, send("DELETE", "/etagbox/", null, null, "If-Match", current).statusCode());
    }

    /**
     * Blob keys must not be derived from the resource path: IRIs are compared case-sensitively but
     * NTFS and default APFS/HFS+ are not, so path-derived keys collapsed two distinct resources
     * onto one file — writing one silently replaced the other's bytes.
     */
    @Test
    void resourcesDifferingOnlyInCaseKeepSeparateBytes() throws Exception {
        assertEquals(201, send("PUT", "/CaseTest", "application/octet-stream", "UPPER-CONTENT").statusCode());
        assertEquals(201, send("PUT", "/casetest", "application/octet-stream", "lower-content").statusCode());

        assertEquals("UPPER-CONTENT", send("GET", "/CaseTest", null, null).body());
        assertEquals("lower-content", send("GET", "/casetest", null, null).body());

        // Deleting one must not remove the other's bytes.
        assertEquals(204, send("DELETE", "/casetest", null, null).statusCode());
        assertEquals("UPPER-CONTENT", send("GET", "/CaseTest", null, null).body());
    }

    /** A data resource and a container of the same name used to collide into a permanent 500. */
    @Test
    void aDataResourceAndAContainerMaySharePrefixes() throws Exception {
        assertEquals(201, send("PUT", "/collide", "application/octet-stream", "FILE").statusCode());
        assertEquals(201, send("PUT", "/collide/", null, null,
                "Link", "<http://www.w3.org/ns/ldp#Container>; rel=\"type\"").statusCode());
        assertEquals(201, send("PUT", "/collide/inner", "application/octet-stream", "INNER").statusCode());

        assertEquals("FILE", send("GET", "/collide", null, null).body());
        assertEquals("INNER", send("GET", "/collide/inner", null, null).body());
    }

    @Test
    void jsonMergePatch() throws Exception {
        HttpResponse<String> created = send("POST", "/", "application/json", "{\"a\":1,\"b\":2}", "Slug", "doc.json");
        assertEquals(201, created.statusCode());
        String resource = path(created.headers().firstValue("Location").orElseThrow());

        // RFC 7386: replace nothing for "a", remove "b" (null), add "c"
        assertEquals(204, send("PATCH", resource, "application/merge-patch+json", "{\"b\":null,\"c\":3}",
                "If-Match", etagOf(resource)).statusCode());

        HttpResponse<String> got = send("GET", resource, null, null);
        assertEquals(200, got.statusCode());
        assertTrue(got.headers().firstValue("Content-Type").orElse("").startsWith("application/json"));
        assertTrue(got.body().contains("\"a\":1"));
        assertTrue(got.body().contains("\"c\":3"));
        assertFalse(got.body().contains("\"b\""), "member b should have been removed");
        assertTrue(got.headers().firstValue("Accept-Patch").orElse("").contains("merge-patch+json"));

        // merge-patch is rejected on a container (409) and on a non-JSON binary (415)
        // Both are refused for what they are, not for a missing precondition: "this method cannot
        // be applied here" is settled before the conditional rule (findings H21, L28).
        assertEquals(409, send("PATCH", "/", "application/merge-patch+json", "{\"x\":1}").statusCode());
        HttpResponse<String> png = send("POST", "/", "image/png", "PNG", "Slug", "blob");
        assertEquals(415, send("PATCH", path(png.headers().firstValue("Location").orElseThrow()),
                "application/merge-patch+json", "{\"x\":1}").statusCode());
    }

    @Test
    void jsonPatch() throws Exception {
        HttpResponse<String> created = send("POST", "/", "application/json", "{\"a\":1,\"b\":2}", "Slug", "jp.json");
        assertEquals(201, created.statusCode());
        String resource = path(created.headers().firstValue("Location").orElseThrow());

        // RFC 6902: replace a, remove b, add c.
        assertEquals(204, send("PATCH", resource, "application/json-patch+json",
                "[{\"op\":\"replace\",\"path\":\"/a\",\"value\":9},{\"op\":\"remove\",\"path\":\"/b\"},"
                        + "{\"op\":\"add\",\"path\":\"/c\",\"value\":3}]",
                "If-Match", etagOf(resource)).statusCode());

        HttpResponse<String> got = send("GET", resource, null, null);
        assertEquals(200, got.statusCode());
        assertTrue(got.body().contains("\"a\":9"));
        assertTrue(got.body().contains("\"c\":3"));
        assertFalse(got.body().contains("\"b\""), "member b should have been removed");
        assertTrue(got.headers().firstValue("Accept-Patch").orElse("").contains("json-patch+json"));

        // A failed `test` op cannot be applied -> 409; JSON Patch is rejected on a container -> 409.
        assertEquals(409, send("PATCH", resource, "application/json-patch+json",
                "[{\"op\":\"test\",\"path\":\"/a\",\"value\":1}]",
                "If-Match", etagOf(resource)).statusCode());
        assertEquals(409, send("PATCH", "/", "application/json-patch+json",
                "[{\"op\":\"add\",\"path\":\"/x\",\"value\":1}]").statusCode());
    }

    @Test
    void managementUiRenders() throws Exception {
        HttpResponse<String> ui = send("GET", "/app/browse", null, null);
        assertEquals(200, ui.statusCode());
        assertTrue(ui.body().contains("LWS Storage"));
    }

    // ----- helpers -----

    /** The current entity-tag of a resource, for a conditional write. */
    private static String etagOf(String path) throws Exception {
        return send("GET", path, null, null).headers().firstValue("ETag").orElseThrow();
    }

    private static HttpResponse<String> send(String method, String path, String contentType, String body,
            String... headerPairs) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path));
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body));
        if (contentType != null) {
            b.header("Content-Type", contentType);
        }
        for (int i = 0; i + 1 < headerPairs.length; i += 2) {
            b.header(headerPairs[i], headerPairs[i + 1]);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String path(String absoluteUrl) {
        return absoluteUrl.substring(baseUrl.length());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
