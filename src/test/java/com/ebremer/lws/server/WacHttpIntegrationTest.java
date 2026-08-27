package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Properties;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * Web Access Control, over HTTP, with a real owner (finding M42).
 *
 * <p>Every other server-booting class in this suite runs in open mode, so between them they assert
 * a great deal about the protocol and nothing whatsoever about authorization: no test reached the
 * ACL endpoint, and none checked that writing an ACL changes what a second agent may read. The WAC
 * engine had unit coverage; the path a client actually takes to it had none.
 *
 * @author Erich Bremer
 */
class WacHttpIntegrationTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}.
     */
    private static final Path tempDir = TestDirs.create();

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;

    /** The configured owner, and a second authenticated agent who is not. */
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
        ownerWebId = owner.did();   // the did:key IS the WebID for this suite
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

    // ----- who may write an ACL -----

    @Test
    void onlyAControllerMayWriteAnAcl() throws Exception {
        assertEquals(201, put("/acl-owner", turtle("v1"), ownerToken).statusCode());

        assertEquals(201, putAcl("/acl-owner", aclGranting(ownerWebId, "Read", "Write", "Control"),
                ownerToken).statusCode(), "the owner controls everything under the root");

        // 404, not 403: Bob has neither Control nor Read here, and a principal without Read is not
        // told whether the resource is there. On the ACL surface that matters more than elsewhere —
        // under WAC, "has an own ACL" is very nearly the same fact as "exists".
        assertEquals(404, putAcl("/acl-owner", aclGranting(bobWebId, "Read", "Write", "Control"),
                bobToken).statusCode(), "Bob has no Control here and must not be able to grant himself any");

        assertEquals(401, putAcl("/acl-owner", aclGranting(bobWebId, "Read"), null).statusCode(),
                "an anonymous client is told to authenticate, not refused outright");

        // And the refused writes changed nothing.
        assertFalse(getAcl("/acl-owner", ownerToken).body().contains(bobWebId),
                "a refused ACL write must not have landed");
    }

    @Test
    void theRootAclCannotBeDeleted() throws Exception {
        HttpResponse<String> deleted = send("DELETE", "/.acl", null, ownerToken);
        assertTrue(deleted.statusCode() == 403 || deleted.statusCode() == 405,
                "removing the root ACL would drop the whole storage to whatever remains: "
                        + deleted.statusCode());
        // The storage is still governed: Bob still cannot read the owner's private resource.
        assertEquals(201, put("/still-guarded", turtle("x"), ownerToken).statusCode());
        // 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, get("/still-guarded", bobToken).statusCode());
    }

    // ----- an ACL actually changes what a second agent may do -----

    @Test
    void writingAnAclChangesWhatAnotherAgentMayRead() throws Exception {
        assertEquals(201, put("/shared", turtle("secret"), ownerToken).statusCode());

        // Before: Bob is authenticated but has no grant of any kind.
// 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, get("/shared", bobToken).statusCode());
        assertEquals(401, get("/shared", null).statusCode());

        // The owner grants Bob Read, and only Read.
        assertEquals(201, putAcl("/shared",
                aclGranting(ownerWebId, "Read", "Write", "Control") + aclGranting(bobWebId, "Read"),
                ownerToken).statusCode());

        HttpResponse<String> bobReads = get("/shared", bobToken);
        assertEquals(200, bobReads.statusCode(), "the grant must take effect immediately");
        assertTrue(bobReads.body().contains("secret"));

        // Read is not Write.
        String etag = bobReads.headers().firstValue("ETag").orElseThrow();
        assertEquals(403, send("PUT", "/shared", turtle("overwritten"), bobToken,
                "Content-Type", "text/turtle", "If-Match", etag).statusCode());
        assertEquals(403, send("DELETE", "/shared", null, bobToken).statusCode());
        assertTrue(get("/shared", ownerToken).body().contains("secret"), "and nothing changed");
    }

    @Test
    void revokingAnAclTakesEffectOnTheNextRequest() throws Exception {
        assertEquals(201, put("/revoked", turtle("v1"), ownerToken).statusCode());
        assertEquals(201, putAcl("/revoked",
                aclGranting(ownerWebId, "Read", "Write", "Control") + aclGranting(bobWebId, "Read"),
                ownerToken).statusCode());
        assertEquals(200, get("/revoked", bobToken).statusCode());

        // Replace the ACL with one that does not name Bob.
        assertEquals(204, putAcl("/revoked", aclGranting(ownerWebId, "Read", "Write", "Control"),
                ownerToken).statusCode());
// 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, get("/revoked", bobToken).statusCode(),
                "authorization is evaluated per request; a revoked grant must not be cached");
    }

    /**
     * Replacing an ACL names the version it replaces, exactly as replacing a resource does
     * (prior-review finding 13).
     *
     * <p>The ACL surface had no conditional-write rule at all, and it is the one place where a lost
     * update <em>grants</em> access nobody chose: two controllers each read the ACL, each add an
     * agent, each write back, and the second silently discards the first — leaving an ACL that names
     * one of the two and looks, to both of them, as though it names both.
     *
     * <p>Every assertion here fails against the pre-fix code, which answered {@code 204} to all
     * three: there was no ACL entity-tag to condition on, so a GET returned none and a PUT compared
     * nothing.
     */
    @Test
    void replacingAnAclIsConditional() throws Exception {
        assertEquals(201, put("/acl-cond", turtle("v1"), ownerToken).statusCode());
        assertEquals(201, putAcl("/acl-cond", aclGranting(ownerWebId, "Read", "Write", "Control"),
                ownerToken).statusCode());

        HttpResponse<String> read = getAcl("/acl-cond", ownerToken);
        String etag = read.headers().firstValue("ETag")
                .orElseThrow(() -> new AssertionError("an ACL carries an entity-tag"));

        String replacement = aclGranting(ownerWebId, "Read", "Write", "Control")
                .replace("<TARGET>", "<" + baseUrl + "/acl-cond>");
        assertEquals(428, send("PUT", "/acl-cond.acl", replacement, ownerToken,
                "Content-Type", "text/turtle").statusCode(), "unconditional replacement is refused");
        assertEquals(412, send("PUT", "/acl-cond.acl", replacement, ownerToken,
                "Content-Type", "text/turtle", "If-Match", "\"deadbeef00000000\"").statusCode());
        assertEquals(204, send("PUT", "/acl-cond.acl", replacement, ownerToken,
                "Content-Type", "text/turtle", "If-Match", etag).statusCode());

        // The tag moved with the write, so the one just used is now stale.
        assertEquals(412, send("PUT", "/acl-cond.acl", replacement, ownerToken,
                "Content-Type", "text/turtle", "If-Match", etag).statusCode());
        // And a conditional read of an unchanged ACL is a 304.
        String current = getAcl("/acl-cond", ownerToken).headers().firstValue("ETag").orElseThrow();
        assertEquals(304, send("GET", "/acl-cond.acl", null, ownerToken,
                "Accept", "text/turtle", "If-None-Match", current).statusCode());
    }

    /** A container's {@code acl:default} governs its members, and an own-ACL outranks it. */
    @Test
    void anOwnAclOutranksAnInheritedDefault() throws Exception {
        assertEquals(201, send("PUT", "/pub/", null, ownerToken,
                "Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"").statusCode());
        assertEquals(201, putAcl("/pub/", aclDefault(ownerWebId, "Read", "Write", "Control")
                + aclDefault(bobWebId, "Read"), ownerToken).statusCode());

        assertEquals(201, put("/pub/open", turtle("readable"), ownerToken).statusCode());
        assertEquals(201, put("/pub/closed", turtle("private"), ownerToken).statusCode());
        assertEquals(200, get("/pub/open", bobToken).statusCode(), "inherited from the container");

        // Give the second child an ACL of its own that does not name Bob.
        assertEquals(201, putAcl("/pub/closed", aclGranting(ownerWebId, "Read", "Write", "Control"),
                ownerToken).statusCode());
// 404, not 403: an authenticated principal without Read is not told whether the
        // resource is there (lws.mask-forbidden-as-not-found).
        assertEquals(404, get("/pub/closed", bobToken).statusCode(),
                "an own-ACL replaces the inherited default rather than adding to it");
        assertEquals(200, get("/pub/open", bobToken).statusCode(), "its sibling is unaffected");

        // The container listing shows Bob only what he may read.
        String listing = get("/pub/", bobToken).body();
        assertTrue(listing.contains("/pub/open"), listing);
        assertFalse(listing.contains("/pub/closed"),
                "a listing that named it would disclose the resource the ACL exists to hide");
    }

    // ----- discovery -----

    @Test
    void responsesAdvertiseTheAclTheyAreGovernedBy() throws Exception {
        assertEquals(201, put("/linked", turtle("x"), ownerToken).statusCode());
        assertTrue(get("/linked", ownerToken).headers().allValues("Link").stream()
                        .anyMatch(l -> l.contains("rel=\"acl\"") && l.contains("/linked.acl")),
                "a client needs the ACL address to manage access without guessing it");
    }

    // ----- helpers -----

    private static String turtle(String name) {
        return "<#it> <http://schema.org/name> \"" + name + "\" .";
    }

    /** One acl:Authorization over the resource itself. */
    private static String aclGranting(String webId, String... modes) {
        return authorization(webId, "acl:accessTo", modes);
    }

    /** One acl:Authorization that also applies to a container's members. */
    private static String aclDefault(String webId, String... modes) {
        return authorization(webId, "acl:accessTo", modes) + authorization(webId, "acl:default", modes);
    }

    private static String authorization(String webId, String scope, String... modes) {
        StringBuilder sb = new StringBuilder("@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n[] a acl:Authorization ; ");
        sb.append(scope).append(" <TARGET> ; acl:agent <").append(webId).append("> ");
        for (String mode : modes) {
            sb.append("; acl:mode acl:").append(mode).append(' ');
        }
        return sb.append(".\n").toString();
    }

    /**
     * Write a target's ACL, naming the version it replaces when there is one.
     *
     * <p>Replacing an ACL is conditional, exactly as replacing a resource is (prior-review finding
     * 13): a lost update on an ACL is a grant of access nobody chose, since two controllers each
     * adding an agent leaves an ACL naming one of them and looking, to both, as though it names
     * both. So this reads the current tag first, which is what a real client does.
     */
    private static HttpResponse<String> putAcl(String targetPath, String aclTurtle, String token)
            throws Exception {
        String body = aclTurtle.replace("<TARGET>", "<" + baseUrl + targetPath + ">");
        String etag = getAcl(targetPath, token).headers().firstValue("ETag").orElse(null);
        return etag == null
                ? send("PUT", targetPath + ".acl", body, token, "Content-Type", "text/turtle")
                : send("PUT", targetPath + ".acl", body, token, "Content-Type", "text/turtle",
                        "If-Match", etag);
    }

    private static HttpResponse<String> getAcl(String targetPath, String token) throws Exception {
        return send("GET", targetPath + ".acl", null, token, "Accept", "text/turtle");
    }

    private static HttpResponse<String> put(String path, String body, String token) throws Exception {
        return send("PUT", path, body, token, "Content-Type", "text/turtle");
    }

    private static HttpResponse<String> get(String path, String token) throws Exception {
        return send("GET", path, null, token, "Accept", "text/turtle");
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
