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

/**
 * End-to-end integration tests: boots the real bare-Jetty stack ({@link JettyLauncher#buildHandler}
 * over a live {@link LwsComponents}) on a free port and drives it with an HTTP client, exercising
 * the full request → filter → servlet → service → store path. Runs in open mode so CRUD needs no
 * credentials.
 *
 * @author Erich Bremer
 */
class EndToEndTest {

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        Path dataDir = Files.createTempDirectory("lws-it");
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "http://localhost:" + port);
        p.setProperty("lws.data-dir", dataDir.toString());
        p.setProperty("lws.webhook.max-attempts", "1");           // fail webhook delivery fast
        p.setProperty("lws.subscription.purge-interval-seconds", "0"); // no background purge during the test
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
        assertTrue(links.stream().anyMatch(l -> l.contains("storageDescription")), "storageDescription Link");

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

        assertEquals(204, send("PATCH", "/box/item", "application/sparql-update",
                "INSERT DATA { <" + baseUrl + "/box/item#x> <http://schema.org/age> 42 }").statusCode());
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
        // A 401 points the client at the storage description so it can discover how to authenticate.
        assertTrue(unauth.headers().allValues("Link").stream().anyMatch(l -> l.contains("storageDescription")),
                "401 should carry a storageDescription Link");
    }

    @Test
    void subscriptionLifecycle() throws Exception {
        String json = "{ \"type\":\"WebhookSubscription\", \"topic\":[\"" + baseUrl + "/\"],"
                + " \"inbox\":\"http://localhost:1/inbox\" }";
        HttpResponse<String> created = send("POST", "/.lws/subscriptions", "application/ld+json", json);
        assertEquals(201, created.statusCode());
        String location = created.headers().firstValue("Location").orElse(null);
        assertNotNull(location);

        assertTrue(send("GET", "/.lws/subscriptions", null, null, "Accept", "text/turtle").body().contains(location));
        assertEquals(200, send("GET", path(location), null, null, "Accept", "text/turtle").statusCode());
        assertEquals(204, send("DELETE", path(location), null, null).statusCode());
    }

    @Test
    void jsonMergePatch() throws Exception {
        HttpResponse<String> created = send("POST", "/", "application/json", "{\"a\":1,\"b\":2}", "Slug", "doc.json");
        assertEquals(201, created.statusCode());
        String resource = path(created.headers().firstValue("Location").orElseThrow());

        // RFC 7386: replace nothing for "a", remove "b" (null), add "c"
        assertEquals(204, send("PATCH", resource, "application/merge-patch+json", "{\"b\":null,\"c\":3}").statusCode());

        HttpResponse<String> got = send("GET", resource, null, null);
        assertEquals(200, got.statusCode());
        assertTrue(got.headers().firstValue("Content-Type").orElse("").startsWith("application/json"));
        assertTrue(got.body().contains("\"a\":1"));
        assertTrue(got.body().contains("\"c\":3"));
        assertFalse(got.body().contains("\"b\""), "member b should have been removed");
        assertTrue(got.headers().firstValue("Accept-Patch").orElse("").contains("merge-patch+json"));

        // merge-patch is rejected on a container (409) and on a non-JSON binary (415)
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
                        + "{\"op\":\"add\",\"path\":\"/c\",\"value\":3}]").statusCode());

        HttpResponse<String> got = send("GET", resource, null, null);
        assertEquals(200, got.statusCode());
        assertTrue(got.body().contains("\"a\":9"));
        assertTrue(got.body().contains("\"c\":3"));
        assertFalse(got.body().contains("\"b\""), "member b should have been removed");
        assertTrue(got.headers().firstValue("Accept-Patch").orElse("").contains("json-patch+json"));

        // A failed `test` op cannot be applied -> 409; JSON Patch is rejected on a container -> 409.
        assertEquals(409, send("PATCH", resource, "application/json-patch+json",
                "[{\"op\":\"test\",\"path\":\"/a\",\"value\":1}]").statusCode());
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
