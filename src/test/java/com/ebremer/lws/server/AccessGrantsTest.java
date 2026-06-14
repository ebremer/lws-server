package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.util.HashSet;
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
 * Integration tests for Access Requests & Grants (lws10-core/lws-access-requests): a storage
 * controller issues a grant that lets another agent read a resource it otherwise cannot, scoped to
 * the granted action, and revoking the grant withdraws the access; plus the request lifecycle,
 * controller-only grant issuance, public grants, discovery advertisement, and error cases.
 *
 * @author Erich Bremer
 */
class AccessGrantsTest {

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;
    private static String ownerToken;
    private static String bobToken;
    private static String bobDid;

    @BeforeAll
    static void start() throws Exception {
        DidKeyTool.Minted owner = DidKeyTool.mint(null, 3600, null);
        DidKeyTool.Minted bob = DidKeyTool.mint(null, 3600, null);
        ownerToken = owner.token();
        bobToken = bob.token();
        bobDid = bob.did();

        int port = freePort();
        baseUrl = "http://localhost:" + port;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.data-dir", Files.createTempDirectory("lws-grants").toString());
        p.setProperty("lws.owners", owner.did());
        p.setProperty("lws.public-read", "false");
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
    void grantEnablesAccessAndRevokeWithdrawsIt() throws Exception {
        assertEquals(201, owner("PUT", "/doc1", "<#it> <http://schema.org/name> \"x\" .", "text/turtle").statusCode());

        // Bob cannot read it (not the owner, not public).
        assertEquals(403, bob("GET", "/doc1", null, null).statusCode());

        // The owner grants Bob read on /doc1.
        String grant = grantJson("[\"read\"]", bobDid, baseUrl + "/doc1");
        HttpResponse<String> created = owner("POST", "/.lws/access-grants", grant, "application/lws+json");
        assertEquals(201, created.statusCode());
        String grantId = created.headers().firstValue("Location").orElseThrow();

        // Now Bob can read it...
        assertEquals(200, bob("GET", "/doc1", null, null).statusCode());
        // ...but only read: writing is still denied (the grant covers "read" only).
        assertEquals(403, bob("PUT", "/doc1", "<#it> <http://schema.org/name> \"y\" .", "text/turtle",
                "If-Match", "*").statusCode());

        // Revoking the grant immediately withdraws the access.
        assertEquals(204, owner("DELETE", path(grantId), null, null).statusCode());
        assertEquals(403, bob("GET", "/doc1", null, null).statusCode());
    }

    @Test
    void publicGrantAllowsAnonymousRead() throws Exception {
        assertEquals(201, owner("PUT", "/doc2", "<#it> <http://schema.org/name> \"x\" .", "text/turtle").statusCode());
        assertEquals(401, send("GET", "/doc2", null, null).statusCode()); // anonymous: unauthenticated

        String grant = grantJson("[\"read\"]", "http://xmlns.com/foaf/0.1/Agent", baseUrl + "/doc2");
        assertEquals(201, owner("POST", "/.lws/access-grants", grant, "application/lws+json").statusCode());

        assertEquals(200, send("GET", "/doc2", null, null).statusCode()); // anonymous now permitted
    }

    @Test
    void requestLifecycle() throws Exception {
        // Anonymous may not submit a request; the 401 points at the storage description.
        HttpResponse<String> anon = send("POST", "/.lws/access-requests",
                requestJson("[\"read\"]", bobDid, baseUrl + "/data/"), "application/lws+json");
        assertEquals(401, anon.statusCode());
        assertTrue(anon.headers().allValues("Link").stream().anyMatch(l -> l.contains("storageDescription")));

        // Bob submits a request, can list and retrieve his own, then cancels it.
        HttpResponse<String> created = bob("POST", "/.lws/access-requests",
                requestJson("[\"read\", \"create\"]", bobDid, baseUrl + "/data/"), "application/lws+json");
        assertEquals(201, created.statusCode());
        String id = created.headers().firstValue("Location").orElseThrow();
        assertTrue(id.startsWith(baseUrl + "/.lws/access-requests/"));

        assertEquals(200, bob("GET", path(id), null, null).statusCode());
        assertTrue(ids(parse(bob("GET", "/.lws/access-requests", null, null).body())).contains(id));

        assertEquals(204, bob("DELETE", path(id), null, null).statusCode());
        assertEquals(404, bob("GET", path(id), null, null).statusCode());
    }

    @Test
    void mediaTypeConstraintGatesTheGrant() throws Exception {
        assertEquals(201, owner("PUT", "/photo", "PNGDATA", "image/png").statusCode());
        assertEquals(403, bob("GET", "/photo", null, null).statusCode());

        // A grant whose mediaType constraint does not match the target does not enable access.
        String mismatch = grantWithConstraint(baseUrl + "/photo", "mediaType", "eq", "image/jpeg");
        String mismatchId = owner("POST", "/.lws/access-grants", mismatch, "application/lws+json")
                .headers().firstValue("Location").orElseThrow();
        assertEquals(403, bob("GET", "/photo", null, null).statusCode());
        assertEquals(204, owner("DELETE", path(mismatchId), null, null).statusCode());

        // A matching mediaType constraint enables it.
        String match = grantWithConstraint(baseUrl + "/photo", "mediaType", "eq", "image/png");
        assertEquals(201, owner("POST", "/.lws/access-grants", match, "application/lws+json").statusCode());
        assertEquals(200, bob("GET", "/photo", null, null).statusCode());
    }

    @Test
    void purposeConstraintGatesTheGrant() throws Exception {
        assertEquals(201, owner("PUT", "/secret", "<#it> <http://schema.org/name> \"x\" .", "text/turtle").statusCode());
        assertEquals(403, bob("GET", "/secret", null, null).statusCode());

        String purpose = "https://purpose.example/research";
        assertEquals(201, owner("POST", "/.lws/access-grants",
                grantWithConstraint(baseUrl + "/secret", "purpose", "eq", purpose), "application/lws+json").statusCode());

        // The grant applies only when the client declares the matching purpose (LWS-Purpose header).
        assertEquals(403, bob("GET", "/secret", null, null).statusCode());                       // none declared
        assertEquals(403, bob("GET", "/secret", null, null, "LWS-Purpose",
                "https://purpose.example/ads").statusCode());                                    // wrong purpose
        assertEquals(200, bob("GET", "/secret", null, null, "LWS-Purpose", purpose).statusCode()); // matching
    }

    @Test
    void onlyAControllerMayIssueAGrant() throws Exception {
        assertEquals(403, bob("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/doc1"), "application/lws+json").statusCode());
    }

    @Test
    void wrongMediaTypeIsRejected() throws Exception {
        assertEquals(415, owner("POST", "/.lws/access-grants",
                grantJson("[\"read\"]", bobDid, baseUrl + "/doc1"), "text/plain").statusCode());
    }

    @Test
    void discoveryAdvertisesAccessServices() throws Exception {
        JsonObject doc = parse(send("GET", "/.lws/storage-description", null, null).body());
        Set<String> serviceTypes = new HashSet<>();
        boolean conformsTo = false;
        for (JsonValue v : doc.getJsonArray("service")) {
            JsonObject s = v.asJsonObject();
            serviceTypes.add(s.getString("type"));
            if (s.getString("type").equals("AccessGrantService") && s.containsKey("conformsTo")) {
                conformsTo = s.getJsonArray("conformsTo").getString(0).equals("https://www.w3.org/ns/lws#AccessProfile");
            }
        }
        assertTrue(serviceTypes.contains("AccessRequestService"), doc.toString());
        assertTrue(serviceTypes.contains("AccessGrantService"), doc.toString());
        assertTrue(conformsTo, "AccessGrantService should advertise the access profile it conforms to");
    }

    // ----- helpers -----

    private static String grantJson(String actions, String assignee, String target) {
        return "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"], \"storage\":\""
                + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"], \"action\":" + actions
                + ", \"assignee\":\"" + assignee + "\", \"target\":{ \"type\":\"StorageResource\", \"value\":[\""
                + target + "\"] } }] }";
    }

    private static String grantWithConstraint(String target, String left, String op, String right) {
        return "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"], \"storage\":\""
                + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"], \"action\":[\"read\"], \"assignee\":\""
                + bobDid + "\", \"target\":{ \"type\":\"StorageResource\", \"value\":[\"" + target + "\"] },"
                + " \"constraint\":[{ \"leftOperand\":\"" + left + "\", \"operator\":\"" + op
                + "\", \"rightOperand\":\"" + right + "\" }] }] }";
    }

    private static String requestJson(String actions, String assignee, String target) {
        return "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessRequest\"], \"storage\":\""
                + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"], \"action\":" + actions
                + ", \"assignee\":\"" + assignee + "\", \"target\":{ \"type\":\"StorageResource\", \"value\":[\""
                + target + "\"] } }] }";
    }

    private static HttpResponse<String> owner(String method, String path, String body, String contentType,
            String... extra) throws Exception {
        return authed(method, path, body, ownerToken, contentType, extra);
    }

    private static HttpResponse<String> bob(String method, String path, String body, String contentType,
            String... extra) throws Exception {
        return authed(method, path, body, bobToken, contentType, extra);
    }

    private static HttpResponse<String> authed(String method, String path, String body, String token,
            String contentType, String... extra) throws Exception {
        String[] headers = headers(token, contentType, extra);
        return send(method, path, body, contentType == null ? null : contentType, headers);
    }

    private static String[] headers(String token, String contentType, String... extra) {
        java.util.List<String> h = new java.util.ArrayList<>();
        h.add("Authorization");
        h.add("Bearer " + token);
        for (int i = 0; i + 1 < extra.length; i += 2) {
            h.add(extra[i]);
            h.add(extra[i + 1]);
        }
        return h.toArray(new String[0]);
    }

    private static HttpResponse<String> send(String method, String path, String body, String contentType,
            String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path));
        if (contentType != null) {
            b.header("Content-Type", contentType);
        }
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String path(String iri) {
        return iri.substring(baseUrl.length());
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
