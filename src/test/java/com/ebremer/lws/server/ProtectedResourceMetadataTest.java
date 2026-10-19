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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * Authorization server discovery as the drafts of 19 October 2026 define it, over real sockets:
 * every {@code 401} challenge carries RFC 9728's {@code resource_metadata}, the URL of the protected
 * resource metadata <em>of the resource requested</em>, and that URL answers with a document whose
 * {@code resource} is the requested URL, character for character, and whose
 * {@code authorization_servers} names where to get a token (lws10-core, Authorization Server
 * Discovery and Protected Resource Metadata).
 *
 * <p>Two storages. One at the root of its host with the defaults — the embedded authorization
 * server, plus a trusted external issuer, the legacy {@code as_uri}/{@code realm} parameters, and a
 * CORS origin. One under a path ({@code lws.base-uri=http://host/lws}) with
 * {@code lws.oauth.legacy-challenge=false} and {@code lws.dpop.require=true}; its proxy, which strips
 * {@code /lws} from storage requests and routes {@code /.well-known/oauth-protected-resource/lws/...}
 * to {@code /.well-known/oauth-protected-resource/...}, is simulated by requesting what the proxy
 * would forward.
 *
 * @author Erich Bremer
 */
class ProtectedResourceMetadataTest {

    private static final Path rootDir = TestDirs.create();
    private static final Path prefixedDir = TestDirs.create();

    private static final String WELL_KNOWN = "/.well-known/oauth-protected-resource";
    private static final String EXTERNAL_AS = "https://as.example";
    private static final String APP = "https://app.example";
    private static final String STORAGE_REL = "https://www.w3.org/ns/lws#storage";
    private static final String DPOP_ALGS = "ES256 ES384 ES512 EdDSA RS256 RS384 RS512 PS256 PS384 PS512";

    private static final HttpClient http = HttpClient.newHttpClient();

    private static Server server;
    private static LwsComponents components;
    private static String base;
    private static String ownerToken;

    private static Server prefixedServer;
    private static LwsComponents prefixedComponents;
    private static String origin;
    private static String prefixedBase;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        base = "http://localhost:" + port;
        DidKeyTool.Minted owner = DidKeyTool.mint(null, 3600, base);
        ownerToken = owner.token();
        Properties p = new Properties();
        p.setProperty("lws.base-uri", base);
        p.setProperty("lws.data-dir", rootDir.toString());
        p.setProperty("lws.owners", owner.did());
        p.setProperty("lws.public-read", "false");
        p.setProperty("lws.oauth.trusted-issuers", EXTERNAL_AS);
        p.setProperty("lws.cors.allowed-origins", APP);
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        assertEquals(201, http.send(HttpRequest.newBuilder(URI.create(base + "/prm/"))
                .header("Authorization", "Bearer " + ownerToken)
                .header("Link", "<https://www.w3.org/ns/lws#Container>; rel=\"type\"")
                .PUT(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString())
                .statusCode());
        assertEquals(201, send("PUT", base + "/prm/doc", "Bearer " + ownerToken, "text/plain", "private")
                .statusCode());

        int prefixedPort = freePort();
        origin = "http://localhost:" + prefixedPort;
        prefixedBase = origin + "/lws";
        Properties q = new Properties();
        q.setProperty("lws.base-uri", prefixedBase);
        q.setProperty("lws.listen-port", Integer.toString(prefixedPort));
        q.setProperty("lws.data-dir", prefixedDir.toString());
        q.setProperty("lws.owners", DidKeyTool.mint(null, 3600, prefixedBase).did());
        q.setProperty("lws.public-read", "false");
        q.setProperty("lws.oauth.legacy-challenge", "false");
        q.setProperty("lws.dpop.require", "true");
        LwsConfiguration prefixedConfig = LwsConfiguration.of(q);
        prefixedComponents = LwsComponents.create(prefixedConfig);
        prefixedServer = new Server(prefixedPort);
        prefixedServer.setHandler(JettyLauncher.buildHandler(prefixedComponents, prefixedConfig));
        prefixedServer.start();
    }

    @AfterAll
    static void stop() throws Exception {
        if (server != null) {
            server.stop();
        }
        if (components != null) {
            components.close();
        }
        if (prefixedServer != null) {
            prefixedServer.stop();
        }
        if (prefixedComponents != null) {
            prefixedComponents.close();
        }
    }

    // ----- the challenge, at the root of a host -----

    /** Both challenges of an anonymous refusal name the container's own metadata, then the legacy parameters. */
    @Test
    void anAnonymousRefusalOfAContainerNamesItsMetadata() throws Exception {
        HttpResponse<String> r = send("GET", base + "/prm/", null, null, null);
        assertEquals(401, r.statusCode());
        String metadata = base + WELL_KNOWN + "/prm/";
        assertEquals(List.of(
                "Bearer resource_metadata=\"" + metadata + "\", as_uri=\"" + base + "\", realm=\"" + base + "/\"",
                "DPoP resource_metadata=\"" + metadata + "\", as_uri=\"" + base + "\", realm=\"" + base
                        + "/\", algs=\"" + DPOP_ALGS + "\""),
                r.headers().allValues("WWW-Authenticate"));
        assertTrue(r.headers().allValues("Link").contains("<" + base + "/>; rel=\"" + STORAGE_REL + "\""),
                "lws10-core: the 401 MUST link to the storage");
        assertEquals(base + "/prm/", follow(r).getString("resource"));
    }

    @Test
    void aDataResourceHasMetadataOfItsOwn() throws Exception {
        HttpResponse<String> r = send("GET", base + "/prm/doc", null, null, null);
        assertEquals(401, r.statusCode());
        assertEquals(base + WELL_KNOWN + "/prm/doc", resourceMetadata(r));
        assertEquals(base + "/prm/doc", follow(r).getString("resource"));
    }

    /** RFC 9728 section 3.1: the query stays after the path, and comes back in {@code resource}. */
    @Test
    void theQueryIsKept() throws Exception {
        HttpResponse<String> r = send("GET", base + "/prm/doc?a=1&b=%20c", null, null, null);
        assertEquals(401, r.statusCode());
        assertEquals(base + WELL_KNOWN + "/prm/doc?a=1&b=%20c", resourceMetadata(r));
        assertEquals(base + "/prm/doc?a=1&b=%20c", follow(r).getString("resource"));
    }

    /** The path is the one the client sent, still percent-encoded: decoding it would change the URL. */
    @Test
    void aPercentEncodedPathIsUsedRaw() throws Exception {
        HttpResponse<String> r = send("GET", base + "/prm/caf%C3%A9%20au%2Blait", null, null, null);
        assertEquals(401, r.statusCode());
        assertEquals(base + WELL_KNOWN + "/prm/caf%C3%A9%20au%2Blait", resourceMetadata(r));
        assertEquals(base + "/prm/caf%C3%A9%20au%2Blait", follow(r).getString("resource"));
    }

    /**
     * The storage root at the root of a host: section 3.1 drops a terminating slash that follows the
     * host, so the metadata URL is the bare well-known path — and it still describes {@code /}.
     */
    @Test
    void theRootContainerAtTheRootOfAHost() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + "/"))
                .header("Accept", "application/lws+json").GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(401, r.statusCode());
        assertEquals(base + WELL_KNOWN, resourceMetadata(r));
        assertEquals(base + "/", follow(r).getString("resource"));
    }

    /** lws10-core: a failed validation's 401 carries {@code resource_metadata} and the error. */
    @Test
    void anInvalidTokenIsRefusedWithTheMetadataAndTheError() throws Exception {
        HttpResponse<String> r = send("GET", base + "/prm/doc", "Bearer not.a.token", null, null);
        assertEquals(401, r.statusCode());
        assertEquals("Bearer resource_metadata=\"" + base + WELL_KNOWN + "/prm/doc\", as_uri=\"" + base
                + "\", realm=\"" + base + "/\", error=\"invalid_token\", error_description=\"invalid or expired "
                + "credential\"", r.headers().firstValue("WWW-Authenticate").orElse(""));
        assertTrue(r.headers().allValues("Link").contains("<" + base + "/>; rel=\"" + STORAGE_REL + "\""));
        assertEquals(base + "/prm/doc", follow(r).getString("resource"));
    }

    // ----- the metadata document -----

    @Test
    void theDocumentNamesTheAuthorizationServersAndTheDpopPolicy() throws Exception {
        HttpResponse<String> r = send("GET", base + WELL_KNOWN + "/prm/doc", null, null, null);
        assertEquals(200, r.statusCode(), r.body());
        assertTrue(r.headers().firstValue("Content-Type").orElse("").startsWith("application/json"));
        assertEquals("public, max-age=3600", r.headers().firstValue("Cache-Control").orElse(""));
        JsonObject md = parse(r.body());
        assertEquals(base + "/prm/doc", md.getString("resource"));
        assertEquals(Json.createArrayBuilder().add(base).add(EXTERNAL_AS).build(),
                md.getJsonArray("authorization_servers"), "the embedded server first, then the trusted one");
        assertEquals(Json.createArrayBuilder().add("header").build(), md.getJsonArray("bearer_methods_supported"));
        assertEquals(DPOP_ALGS, String.join(" ", md.getJsonArray("dpop_signing_alg_values_supported")
                .getValuesAs(jakarta.json.JsonString::getString)));
        assertFalse(md.getBoolean("dpop_bound_access_tokens_required"));
    }

    /**
     * No existence oracle: an existing private resource, an absent one, a system endpoint and the
     * root get the same document apart from the {@code resource} they asked about — and none of it
     * needs a credential, nor is refused for carrying a bad one.
     */
    @Test
    void theDocumentIsTheSameForEveryPathAndNeedsNoAuthentication() throws Exception {
        String expected = withoutResource(send("GET", base + WELL_KNOWN + "/prm/doc", null, null, null));
        for (String path : new String[] {"/prm/absent", "/prm/", "/.lws/subscriptions", "", "/nowhere/x?y=z"}) {
            HttpResponse<String> r = send("GET", base + WELL_KNOWN + path, null, null, null);
            assertEquals(200, r.statusCode(), path);
            assertEquals(expected, withoutResource(r), path);
        }
        for (String authorization : new String[] {"Bearer not.a.token", "DPoP not.a.token", "SAML2 bm90",
                "Bearer " + ownerToken}) {
            HttpResponse<String> r = send("GET", base + WELL_KNOWN + "/prm/doc", authorization, null, null);
            assertEquals(200, r.statusCode(), authorization + ": " + r.headers().firstValue("WWW-Authenticate"));
            assertFalse(r.headers().firstValue("WWW-Authenticate").isPresent());
            assertEquals(expected, withoutResource(r), authorization);
        }
    }

    @Test
    void headOptionsAndOtherMethods() throws Exception {
        HttpResponse<String> get = send("GET", base + WELL_KNOWN + "/prm/doc", null, null, null);
        HttpResponse<String> head = send("HEAD", base + WELL_KNOWN + "/prm/doc", null, null, null);
        assertEquals(200, head.statusCode());
        assertEquals("", head.body());
        assertEquals(get.headers().firstValue("Content-Length"), head.headers().firstValue("Content-Length"));
        assertEquals(get.headers().firstValue("Content-Type"), head.headers().firstValue("Content-Type"));

        HttpResponse<String> options = send("OPTIONS", base + WELL_KNOWN + "/prm/doc", null, null, null);
        assertEquals(204, options.statusCode());
        assertEquals("GET, HEAD, OPTIONS", options.headers().firstValue("Allow").orElse(""));

        // Nothing can be written under the well-known path: the metadata servlet owns it.
        HttpResponse<String> put = send("PUT", base + WELL_KNOWN + "/x", "Bearer " + ownerToken, "text/plain", "x");
        assertEquals(405, put.statusCode());
        assertEquals("GET, HEAD, OPTIONS", put.headers().firstValue("Allow").orElse(""));
        assertTrue(LwsConfiguration.of(props("http://localhost:1")).isReservedPath(WELL_KNOWN + "/x"));
    }

    /** Readable from a browser application on an allowed origin, as the refusal that points to it is. */
    @Test
    void theDocumentIsReadableCrossOrigin() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + WELL_KNOWN + "/prm/doc"))
                .header("Origin", APP).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode());
        assertEquals(APP, r.headers().firstValue("Access-Control-Allow-Origin").orElse(""));

        HttpResponse<String> preflight = http.send(HttpRequest.newBuilder(URI.create(base + WELL_KNOWN + "/prm/doc"))
                .header("Origin", APP).header("Access-Control-Request-Method", "GET")
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(204, preflight.statusCode());
        assertEquals(APP, preflight.headers().firstValue("Access-Control-Allow-Origin").orElse(""));

        // And the challenge that leads there is readable too.
        HttpResponse<String> refused = http.send(HttpRequest.newBuilder(URI.create(base + "/prm/doc"))
                .header("Origin", APP).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(401, refused.statusCode());
        assertTrue(refused.headers().firstValue("Access-Control-Expose-Headers").orElse("")
                .contains("WWW-Authenticate"));
    }

    // ----- under a base path, legacy parameters off, DPoP required -----

    /**
     * The metadata URL keeps the base path after the well-known one (RFC 9728 section 3.1), although
     * the proxy stripped it from the request this server received; without the legacy parameters the
     * challenge is exactly what the current drafts define.
     */
    @Test
    void underABasePathTheMetadataUrlCarriesIt() throws Exception {
        HttpResponse<String> r = send("GET", origin + "/c/doc?x=1", null, null, null);
        assertEquals(401, r.statusCode());
        String metadata = origin + WELL_KNOWN + "/lws/c/doc?x=1";
        assertEquals(List.of("Bearer resource_metadata=\"" + metadata + "\"",
                "DPoP resource_metadata=\"" + metadata + "\", algs=\"" + DPOP_ALGS + "\""),
                r.headers().allValues("WWW-Authenticate"));
        assertTrue(r.headers().allValues("Link").contains("<" + prefixedBase + "/>; rel=\"" + STORAGE_REL + "\""));

        HttpResponse<String> root = http.send(HttpRequest.newBuilder(URI.create(origin + "/"))
                .header("Accept", "application/lws+json").GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(401, root.statusCode());
        assertTrue(root.headers().allValues("WWW-Authenticate")
                .contains("Bearer resource_metadata=\"" + origin + WELL_KNOWN + "/lws/\""),
                root.headers().allValues("WWW-Authenticate").toString());
    }

    /** What the proxy forwards from {@code /.well-known/oauth-protected-resource/lws/...} describes {@code /lws/...}. */
    @Test
    void underABasePathTheDocumentPutsItBack() throws Exception {
        assertEquals(prefixedBase + "/c/doc?x=1", metadata(origin + WELL_KNOWN + "/c/doc?x=1").getString("resource"));
        assertEquals(prefixedBase + "/", metadata(origin + WELL_KNOWN + "/").getString("resource"));
        assertEquals(prefixedBase, metadata(origin + WELL_KNOWN).getString("resource"));
        JsonObject md = metadata(origin + WELL_KNOWN + "/c/doc");
        assertEquals(Json.createArrayBuilder().add(prefixedBase).build(), md.getJsonArray("authorization_servers"));
        assertTrue(md.getBoolean("dpop_bound_access_tokens_required"), "lws.dpop.require=true");
    }

    /** A refused credential, DPoP being required: the DPoP challenge, the metadata, the error. */
    @Test
    void aRefusedCredentialUnderABasePath() throws Exception {
        HttpResponse<String> r = send("GET", origin + "/c/doc", "Bearer not.a.token", null, null);
        assertEquals(401, r.statusCode());
        assertEquals("DPoP resource_metadata=\"" + origin + WELL_KNOWN + "/lws/c/doc\", algs=\"" + DPOP_ALGS
                + "\", error=\"invalid_token\", error_description=\"this storage requires DPoP-bound access tokens\"",
                r.headers().firstValue("WWW-Authenticate").orElse(""));
    }

    // ----- helpers -----

    /** The {@code resource_metadata} of a response's Bearer challenge, asserting every challenge agrees. */
    private static String resourceMetadata(HttpResponse<String> response) {
        String found = null;
        for (String challenge : response.headers().allValues("WWW-Authenticate")) {
            Matcher m = Pattern.compile("resource_metadata=\"([^\"]+)\"").matcher(challenge);
            assertTrue(m.find(), challenge);
            if (found != null) {
                assertEquals(found, m.group(1), "every challenge names the same metadata");
            }
            found = m.group(1);
        }
        assertTrue(found != null, "no WWW-Authenticate");
        return found;
    }

    /** Fetch the metadata a refusal points to, as a client does: anonymously, from the same origin. */
    private static JsonObject follow(HttpResponse<String> refused) throws Exception {
        String url = resourceMetadata(refused);
        URI requested = refused.request().uri();
        URI metadata = URI.create(url);
        assertEquals(requested.getScheme() + "://" + requested.getRawAuthority(),
                metadata.getScheme() + "://" + metadata.getRawAuthority());
        return metadata(url);
    }

    private static JsonObject metadata(String url) throws Exception {
        HttpResponse<String> r = send("GET", url, null, null, null);
        assertEquals(200, r.statusCode(), url + ": " + r.body());
        return parse(r.body());
    }

    private static String withoutResource(HttpResponse<String> r) {
        return Json.createObjectBuilder(parse(r.body())).remove("resource").build().toString();
    }

    private static Properties props(String baseUri) {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUri);
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        return p;
    }

    private static HttpResponse<String> send(String method, String url, String authorization, String contentType,
            String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body));
        if (authorization != null) {
            b.header("Authorization", authorization);
        }
        if (contentType != null) {
            b.header("Content-Type", contentType);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static JsonObject parse(String json) {
        try (var reader = Json.createReader(new StringReader(json))) {
            return reader.readObject();
        }
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
