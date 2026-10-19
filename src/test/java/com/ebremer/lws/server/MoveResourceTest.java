package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * Moving resources between containers over HTTP (lws10-core, Moving Resources), under Web Access
 * Control with a real owner and a second agent: the draft's own example of a server that assigns a
 * new identifier, what a previous identifier answers and to whom, a container moving with what it
 * holds and the ACLs that govern it, the refusals, and the three forms a linkset write can take.
 *
 * @author Erich Bremer
 */
class MoveResourceTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}.
     */
    private static final Path tempDir = TestDirs.create();

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;

    private static String ownerWebId;
    private static String ownerToken;
    private static String bobWebId;
    private static String bobToken;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        DidKeyTool.Minted owner = DidKeyTool.mint(null, 3600, baseUrl);
        DidKeyTool.Minted bob = DidKeyTool.mint(null, 3600, baseUrl);
        ownerToken = owner.token();
        bobToken = bob.token();
        ownerWebId = owner.did();
        bobWebId = bob.did();

        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.access-control", "wac");
        p.setProperty("lws.owners", ownerWebId);
        p.setProperty("lws.data-dir", tempDir.toString());
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        // Redirect.NEVER, the default: a 301 is part of what is under test.
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
    void theStorageDescriptionSaysMovedResourcesGetNewIdentifiers() throws Exception {
        JsonObject description = json(send("GET", "/", null, null, "Accept", "application/lws+cid").body());
        JsonObject move = description.getJsonArray("capability").stream().map(JsonValue::asJsonObject)
                .filter(c -> "MoveResource".equals(c.getString("type", null))).findFirst().orElseThrow();
        assertEquals(List.of("DataResource", "Container"),
                move.getJsonArray("appliesTo").getValuesAs(jakarta.json.JsonString::getString));
        assertEquals(JsonValue.FALSE, move.get("preservesIdentifier"));
    }

    // ----- the draft's example: a server that derives identifiers from the hierarchy -----

    @Test
    void theDraftsExampleMovesADataResourceAndReportsItsNewIdentifiers() throws Exception {
        container("/ex/");
        container("/ex/notes/");
        container("/ex/archive/");
        assertEquals(201, send("PUT", "/ex/notes/shoppinglist.txt", "eggs, milk", ownerToken,
                "Content-Type", "text/plain").statusCode());
        assertEquals(204, patchLinkset("/ex/notes/shoppinglist.txt", "[{\"op\":\"add\",\"path\":\"/linkset/0/license\","
                + "\"value\":[{\"href\":\"https://creativecommons.org/licenses/by/4.0/\"}]}]").statusCode());
        String notesTag = etag("/ex/notes/");
        String archiveTag = etag("/ex/archive/");
        String old = baseUrl + "/ex/notes/shoppinglist.txt";

        // The draft's patch, guarded by a test of the anchor as its note suggests, with the
        // destination as a path-absolute reference, as in its example.
        HttpResponse<String> moved = patchLinkset("/ex/notes/shoppinglist.txt",
                "[{\"op\":\"test\",\"path\":\"/linkset/0/anchor\",\"value\":\"" + old + "\"},"
                        + "{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\"/ex/archive/\"}]");

        assertEquals(200, moved.statusCode(), moved.body());
        assertTrue(moved.headers().firstValue("Content-Type").orElseThrow().startsWith("application/linkset+json"));
        String now = baseUrl + "/ex/archive/shoppinglist.txt";
        assertEquals(now + ".meta", moved.headers().firstValue("Content-Location").orElseThrow());
        JsonObject context = json(moved.body()).getJsonArray("linkset").getJsonObject(0);
        assertEquals(now, context.getString("anchor"));
        assertEquals(baseUrl + "/ex/archive/", context.getJsonArray("up").getJsonObject(0).getString("href"));
        assertEquals(now + ".meta", context.getJsonArray("linkset").getJsonObject(0).getString("href"));
        assertEquals("https://creativecommons.org/licenses/by/4.0/",
                context.getJsonArray("license").getJsonObject(0).getString("href"), "user metadata is kept");
        assertEquals(moved.headers().firstValue("ETag").orElseThrow(),
                send("GET", "/ex/archive/shoppinglist.txt.meta", null, ownerToken).headers()
                        .firstValue("ETag").orElseThrow(), "the tag of the linkset at its new address");

        HttpResponse<String> read = send("GET", "/ex/archive/shoppinglist.txt", null, ownerToken);
        assertEquals(200, read.statusCode());
        assertEquals("eggs, milk", read.body(), "content is unaffected by a move");
        assertTrue(read.headers().allValues("Link").stream()
                .anyMatch(l -> l.contains("<" + baseUrl + "/ex/archive/>") && l.contains("rel=\"up\"")));

        assertEquals(List.of(), ids("/ex/notes/"), "removed from the container it left");
        assertEquals(List.of(now), ids("/ex/archive/"), "and added to the one it joined");
        assertNotEquals(notesTag, etag("/ex/notes/"));
        assertNotEquals(archiveTag, etag("/ex/archive/"));

        // The previous identifiers redirect — the resource's and its auxiliary resources' — for
        // whoever may read it where it went...
        assertRedirect(send("GET", "/ex/notes/shoppinglist.txt", null, ownerToken), now);
        assertRedirect(send("HEAD", "/ex/notes/shoppinglist.txt", null, ownerToken), now);
        assertRedirect(send("GET", "/ex/notes/shoppinglist.txt.meta", null, ownerToken), now + ".meta");
        assertRedirect(send("GET", "/ex/notes/shoppinglist.txt.acl", null, ownerToken), now + ".acl");
        // ...and are refused exactly as before for anyone else, so the redirect is no oracle.
        assertEquals(404, send("GET", "/ex/notes/shoppinglist.txt", null, bobToken).statusCode());
        assertEquals(404, send("GET", "/ex/notes/shoppinglist.txt.meta", null, bobToken).statusCode());
        assertEquals(401, send("GET", "/ex/notes/shoppinglist.txt", null, null).statusCode());
        // Only reads redirect.
        assertEquals(404, send("DELETE", "/ex/notes/shoppinglist.txt", null, ownerToken).statusCode());
    }

    @Test
    void aMoveIsAConditionalWriteOfTheLinkset() throws Exception {
        container("/cw/");
        container("/cw/a/");
        container("/cw/b/");
        assertEquals(201, send("PUT", "/cw/a/x", "x", ownerToken, "Content-Type", "text/plain").statusCode());
        String patch = "[{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\"" + baseUrl + "/cw/b/\"}]";

        assertEquals(428, send("PATCH", "/cw/a/x.meta", patch, ownerToken,
                "Content-Type", "application/json-patch+json").statusCode());
        assertEquals(412, send("PATCH", "/cw/a/x.meta", patch, ownerToken,
                "Content-Type", "application/json-patch+json", "If-Match", "\"0123456789abcdef\"").statusCode());
        assertEquals(List.of(baseUrl + "/cw/a/x"), ids("/cw/a/"), "neither moved anything");
        assertEquals(List.of(), ids("/cw/b/"));
    }

    // ----- a container moves with what it holds, and what governs it -----

    @Test
    void aContainerMovesWithItsMembersTheirMetadataAndTheirAcls() throws Exception {
        container("/mc/");
        container("/mc/src/");
        container("/mc/dst/");
        container("/mc/src/proj/");
        assertEquals(201, send("PUT", "/mc/src/proj/data.ttl", "<#it> <http://schema.org/name> \"d\" .",
                ownerToken, "Content-Type", "text/turtle").statusCode());
        assertEquals(204, patchLinkset("/mc/src/proj/data.ttl", "[{\"op\":\"add\",\"path\":\"/linkset/0/describedby\","
                + "\"value\":[{\"href\":\"https://shapes.example/S\"}]}]").statusCode());
        // Bob may read the project, and only because of the project's own ACL.
        assertEquals(201, putAcl("/mc/src/proj/", aclDefault(ownerWebId, "Read", "Write", "Control")
                + aclDefault(bobWebId, "Read")).statusCode());
        assertEquals(200, send("GET", "/mc/src/proj/data.ttl", null, bobToken).statusCode());

        HttpResponse<String> moved = patchLinkset("/mc/src/proj/",
                "[{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\"" + baseUrl + "/mc/dst/\"}]");
        assertEquals(200, moved.statusCode(), moved.body());
        assertEquals(baseUrl + "/mc/dst/proj/.meta", moved.headers().firstValue("Content-Location").orElseThrow());

        assertEquals(List.of(), ids("/mc/src/"));
        assertEquals(List.of(baseUrl + "/mc/dst/proj/"), ids("/mc/dst/"));
        assertEquals(List.of(baseUrl + "/mc/dst/proj/data.ttl"), ids("/mc/dst/proj/"));
        assertTrue(send("GET", "/mc/dst/proj/data.ttl.meta", null, ownerToken).body()
                .contains("https://shapes.example/S"), "a member's metadata moved with it");
        // The ACL moved with the container and names it where it is now, so it still grants.
        assertEquals(200, send("GET", "/mc/dst/proj/data.ttl", null, bobToken).statusCode());
        String acl = send("GET", "/mc/dst/proj/.acl", null, ownerToken, "Accept", "text/turtle").body();
        assertTrue(acl.contains(baseUrl + "/mc/dst/proj/"), acl);
        assertFalse(acl.contains(baseUrl + "/mc/src/proj/"), acl);

        // A member's previous IRI redirects through the container's record, for Bob too.
        assertRedirect(send("GET", "/mc/src/proj/data.ttl", null, bobToken), baseUrl + "/mc/dst/proj/data.ttl");
        assertRedirect(send("GET", "/mc/src/proj/", null, ownerToken), baseUrl + "/mc/dst/proj/");
    }

    @Test
    void aContainerCannotMoveIntoItsOwnDescendant() throws Exception {
        container("/cy/");
        container("/cy/notes/");
        container("/cy/notes/2026/");

        HttpResponse<String> refused = patchLinkset("/cy/notes/",
                "[{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\"/cy/notes/2026/\"}]");

        assertEquals(409, refused.statusCode());
        assertTrue(refused.headers().firstValue("Content-Type").orElseThrow().startsWith("application/problem+json"));
        JsonObject problem = json(refused.body());
        assertEquals("Cannot move a container into one of its own descendants", problem.getString("title"));
        assertEquals(409, problem.getInt("status"));
        assertEquals(baseUrl + "/cy/notes/2026/ is a descendant of " + baseUrl + "/cy/notes/",
                problem.getString("detail"));
        assertEquals(List.of(baseUrl + "/cy/notes/"), ids("/cy/"));
    }

    @Test
    void refusesAnUpThatNamesNoContainerOrNone() throws Exception {
        container("/iv/");
        assertEquals(201, send("PUT", "/iv/x", "x", ownerToken, "Content-Type", "text/plain").statusCode());
        assertEquals(201, send("PUT", "/iv/y", "y", ownerToken, "Content-Type", "text/plain").statusCode());
        for (String patch : List.of(
                "[{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\"/iv/nowhere/\"}]",
                "[{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\"/iv/y\"}]",
                "[{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\"https://elsewhere.example/\"}]",
                "[{\"op\":\"remove\",\"path\":\"/linkset/0/up\"}]",
                "[{\"op\":\"add\",\"path\":\"/linkset/0/up/-\",\"value\":{\"href\":\"/\"}}]")) {
            int status = patchLinkset("/iv/x", patch).statusCode();
            assertTrue(status >= 400 && status < 500, status + " for " + patch);
        }
        assertEquals(List.of(baseUrl + "/iv/x", baseUrl + "/iv/y"), ids("/iv/"));
    }

    // ----- the other forms of a linkset write -----

    @Test
    void theMergePatchAndPutFormsMoveTooAndTheRelationMapRefusesUp() throws Exception {
        container("/fm/");
        container("/fm/a/");
        container("/fm/b/");
        container("/fm/c/");
        assertEquals(201, send("PUT", "/fm/a/r", "r", ownerToken, "Content-Type", "text/plain").statusCode());

        // JSON Merge Patch, in the document form a GET returns...
        HttpResponse<String> byDocument = send("PATCH", "/fm/a/r.meta", "{\"linkset\":[{\"anchor\":\"" + baseUrl
                + "/fm/a/r\",\"up\":[{\"href\":\"" + baseUrl + "/fm/b/\"}]}]}", ownerToken,
                "Content-Type", "application/merge-patch+json", "If-Match", linksetTag("/fm/a/r"));
        assertEquals(200, byDocument.statusCode(), byDocument.body());
        assertEquals(baseUrl + "/fm/b/r.meta", byDocument.headers().firstValue("Content-Location").orElseThrow());

        // ...and in the relation-map form.
        HttpResponse<String> byMap = send("PATCH", "/fm/b/r.meta", "{\"up\":[{\"href\":\"../c/\"}]}", ownerToken,
                "Content-Type", "application/merge-patch+json", "If-Match", linksetTag("/fm/b/r"));
        assertEquals(200, byMap.statusCode(), byMap.body());
        assertEquals(baseUrl + "/fm/c/r.meta", byMap.headers().firstValue("Content-Location").orElseThrow());

        // A PUT of the whole document, edited.
        String document = send("GET", "/fm/c/r.meta", null, ownerToken).body()
                .replace(baseUrl + "/fm/c/\"", baseUrl + "/fm/a/\"");
        HttpResponse<String> byPut = send("PUT", "/fm/c/r.meta", document, ownerToken,
                "Content-Type", "application/linkset+json", "If-Match", linksetTag("/fm/c/r"));
        assertEquals(200, byPut.statusCode(), byPut.body());
        assertEquals(baseUrl + "/fm/a/r.meta", byPut.headers().firstValue("Content-Location").orElseThrow());

        // A PUT that leaves up out keeps it, and answers as any other linkset write.
        HttpResponse<String> keeps = send("PUT", "/fm/a/r.meta", "{\"linkset\":[{\"anchor\":\"" + baseUrl
                + "/fm/a/r\",\"license\":[{\"href\":\"https://example.org/l\"}]}]}", ownerToken,
                "Content-Type", "application/linkset+json", "If-Match", linksetTag("/fm/a/r"));
        assertEquals(204, keeps.statusCode());

        // JSON Patch addressed to the relation map, which never holds up, is refused, not ignored.
        assertEquals(409, send("PATCH", "/fm/a/r.meta", "[{\"op\":\"add\",\"path\":\"/up\","
                + "\"value\":[{\"href\":\"" + baseUrl + "/fm/b/\"}]}]", ownerToken,
                "Content-Type", "application/json-patch+json", "If-Match", linksetTag("/fm/a/r")).statusCode());
        assertEquals(List.of(baseUrl + "/fm/a/r"), ids("/fm/a/"));
    }

    // ----- who may move what, under Web Access Control -----

    @Test
    void bobMayMoveOnlyIntoAContainerHeMayCreateIn() throws Exception {
        container("/az/");
        container("/az/src/");
        container("/az/dst/");
        assertEquals(201, send("PUT", "/az/src/res.txt", "bob's", ownerToken,
                "Content-Type", "text/plain").statusCode());
        assertEquals(201, putAcl("/az/src/res.txt", aclGranting(ownerWebId, "Read", "Write", "Control")
                + aclGranting(bobWebId, "Read", "Write")).statusCode());
        assertEquals(201, putAcl("/az/dst/", aclDefault(ownerWebId, "Read", "Write", "Control")
                + aclGranting(bobWebId, "Read")).statusCode());
        String patch = "[{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\"" + baseUrl + "/az/dst/\"}]";

        // Bob may write the linkset, and delete the resource (acl:Write), but not create in /az/dst/.
        assertEquals(403, send("PATCH", "/az/src/res.txt.meta", patch, bobToken,
                "Content-Type", "application/json-patch+json", "If-Match", linksetTag("/az/src/res.txt")).statusCode());
        assertEquals(List.of(), ids("/az/dst/"));

        // Given Append there, he may; and the resource's own ACL follows it, so he still may write it.
        assertEquals(204, putAcl("/az/dst/", aclDefault(ownerWebId, "Read", "Write", "Control")
                + aclGranting(bobWebId, "Read", "Append")).statusCode());
        HttpResponse<String> moved = send("PATCH", "/az/src/res.txt.meta", patch, bobToken,
                "Content-Type", "application/json-patch+json", "If-Match", linksetTag("/az/src/res.txt"));
        assertEquals(200, moved.statusCode(), moved.body());
        String tag = send("GET", "/az/dst/res.txt", null, bobToken).headers().firstValue("ETag").orElseThrow();
        assertEquals(204, send("PUT", "/az/dst/res.txt", "still bob's", bobToken,
                "Content-Type", "text/plain", "If-Match", tag).statusCode());
    }

    @Test
    void aContainerHoldingSomethingBobMayNotDeleteDoesNotMove() throws Exception {
        container("/az2/");
        container("/az2/c/");
        container("/az2/d/");
        assertEquals(201, send("PUT", "/az2/c/open", "o", ownerToken, "Content-Type", "text/plain").statusCode());
        assertEquals(201, send("PUT", "/az2/c/secret", "s", ownerToken, "Content-Type", "text/plain").statusCode());
        assertEquals(201, putAcl("/az2/c/", aclDefault(ownerWebId, "Read", "Write", "Control")
                + aclDefault(bobWebId, "Read", "Write")).statusCode());
        assertEquals(201, putAcl("/az2/c/secret", aclGranting(ownerWebId, "Read", "Write", "Control")).statusCode());
        assertEquals(201, putAcl("/az2/d/", aclDefault(ownerWebId, "Read", "Write", "Control")
                + aclDefault(bobWebId, "Read", "Write")).statusCode());

        HttpResponse<String> refused = send("PATCH", "/az2/c/.meta",
                "[{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\"" + baseUrl + "/az2/d/\"}]",
                bobToken, "Content-Type", "application/json-patch+json", "If-Match", linksetTag("/az2/c/"));

        assertTrue(refused.statusCode() == 403 || refused.statusCode() == 404,
                refused.statusCode() + " " + refused.body());
        assertFalse(refused.body().contains("secret"), "a member Bob may not read is not named to him");
        assertEquals(List.of(baseUrl + "/az2/c/open", baseUrl + "/az2/c/secret"), ids("/az2/c/"), "nothing moved");
        assertEquals(List.of(), ids("/az2/d/"));
    }

    // ----- helpers -----

    private static void assertRedirect(HttpResponse<String> response, String location) {
        assertEquals(301, response.statusCode());
        assertEquals(location, response.headers().firstValue("Location").orElseThrow());
    }

    private static void container(String path) throws Exception {
        assertEquals(201, send("PUT", path, null, ownerToken).statusCode(), path);
    }

    private static HttpResponse<String> patchLinkset(String path, String jsonPatch) throws Exception {
        return send("PATCH", path + ".meta", jsonPatch, ownerToken,
                "Content-Type", "application/json-patch+json", "If-Match", linksetTag(path));
    }

    private static String linksetTag(String path) throws Exception {
        return send("GET", path + ".meta", null, ownerToken).headers().firstValue("ETag").orElseThrow();
    }

    private static String etag(String containerPath) throws Exception {
        return send("GET", containerPath, null, ownerToken, "Accept", "application/lws+json").headers()
                .firstValue("ETag").orElseThrow();
    }

    /** The ids a container lists, as its owner sees them. */
    private static List<String> ids(String containerPath) throws Exception {
        JsonArray items = json(send("GET", containerPath, null, ownerToken, "Accept", "application/lws+json").body())
                .getJsonArray("items");
        return items.stream().map(v -> v.asJsonObject().getString("id")).toList();
    }

    private static JsonObject json(String body) {
        return Json.createReader(new StringReader(body)).readObject();
    }

    private static String aclGranting(String webId, String... modes) {
        return authorization(webId, "acl:accessTo", modes);
    }

    private static String aclDefault(String webId, String... modes) {
        return authorization(webId, "acl:accessTo", modes) + authorization(webId, "acl:default", modes);
    }

    private static String authorization(String webId, String scope, String... modes) {
        StringBuilder sb = new StringBuilder(
                "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n[] a acl:Authorization ; ");
        sb.append(scope).append(" <TARGET> ; acl:agent <").append(webId).append("> ");
        for (String mode : modes) {
            sb.append("; acl:mode acl:").append(mode).append(' ');
        }
        return sb.append(".\n").toString();
    }

    private static HttpResponse<String> putAcl(String targetPath, String aclTurtle) throws Exception {
        String body = aclTurtle.replace("<TARGET>", "<" + baseUrl + targetPath + ">");
        String etag = send("GET", targetPath + ".acl", null, ownerToken, "Accept", "text/turtle").headers()
                .firstValue("ETag").orElse(null);
        return etag == null
                ? send("PUT", targetPath + ".acl", body, ownerToken, "Content-Type", "text/turtle")
                : send("PUT", targetPath + ".acl", body, ownerToken, "Content-Type", "text/turtle", "If-Match", etag);
    }

    private static HttpResponse<String> send(String method, String path, String body, String token,
            String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path));
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
