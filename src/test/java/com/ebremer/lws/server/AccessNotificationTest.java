package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import com.sun.net.httpserver.HttpServer;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * Verifies access-event notifications (lws10-core access requests): a creation notification (signed
 * {@code lws:Notification}) is delivered to the document's own {@code inbox}, to the configured
 * storage-controller inbox for a new request, and to the associated request's inbox for a grant that
 * links to it via a {@code request} reference.
 *
 * @author Erich Bremer
 */
class AccessNotificationTest {

    private record Received(String contentType, String contentDigest, String signatureInput,
            String signature, byte[] body) {
        boolean is(String text) {
            return new String(body, StandardCharsets.UTF_8).contains(text);
        }
    }

    private static Server lws;
    private static LwsComponents components;
    private static HttpServer inbox;
    private static String inboxUrl;
    private static String baseUrl;
    private static HttpClient http;
    private static String ownerToken;
    private static String bobToken;
    private static String bobDid;

    private static final CopyOnWriteArrayList<Received> received = new CopyOnWriteArrayList<>();

    @BeforeAll
    static void start() throws Exception {
        inbox = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        inboxUrl = "http://localhost:" + inbox.getAddress().getPort() + "/inbox";
        inbox.createContext("/inbox", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            received.add(new Received(
                    exchange.getRequestHeaders().getFirst("Content-Type"),
                    exchange.getRequestHeaders().getFirst("Content-Digest"),
                    exchange.getRequestHeaders().getFirst("Signature-Input"),
                    exchange.getRequestHeaders().getFirst("Signature"), body));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        inbox.start();

        DidKeyTool.Minted owner = DidKeyTool.mint(null, 3600, null);
        DidKeyTool.Minted bob = DidKeyTool.mint(null, 3600, null);
        ownerToken = owner.token();
        bobToken = bob.token();
        bobDid = bob.did();

        int port = freePort();
        baseUrl = "http://localhost:" + port;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.data-dir", Files.createTempDirectory("lws-access-notify").toString());
        p.setProperty("lws.owners", owner.did());
        p.setProperty("lws.access-requests.controller-inbox", inboxUrl);
        p.setProperty("lws.webhook.max-attempts", "1");
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        lws = new Server(port);
        lws.setHandler(JettyLauncher.buildHandler(components, config));
        lws.start();
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void stop() throws Exception {
        if (lws != null) {
            lws.stop();
        }
        if (components != null) {
            components.close();
        }
        if (inbox != null) {
            inbox.stop(0);
        }
    }

    @Test
    void grantWithOwnInboxIsNotifiedAndSigned() throws Exception {
        String grant = "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"], \"storage\":\""
                + baseUrl + "/\", \"inbox\":\"" + inboxUrl + "\", \"access\":[{ \"type\":[\"AccessPolicy\"],"
                + " \"action\":[\"read\"], \"assignee\":\"" + bobDid + "\","
                + " \"target\":{ \"type\":\"StorageResource\", \"value\":[\"" + baseUrl + "/doc\"] } }] }";
        String grantId = create("/.lws/access-grants", grant, ownerToken);

        Received r = await(n -> n.is("AccessGrant") && n.is(grantId));
        assertTrue(r.contentType().startsWith("application/ld+json"), r.contentType());
        assertTrue(r.is("Notification") && r.is("Create"));
        // Signed delivery (RFC 9421) with a matching Content-Digest (RFC 9530).
        assertTrue(r.signatureInput() != null && r.signature() != null, "signed delivery");
        String expectedDigest = "sha-256=:" + Base64.getEncoder()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(r.body())) + ":";
        assertEquals(expectedDigest, r.contentDigest());
    }

    @Test
    void newRequestNotifiesTheControllerInbox() throws Exception {
        // No own inbox on the request: only the configured controller inbox fires.
        String request = "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessRequest\"], \"storage\":\""
                + baseUrl + "/\", \"access\":[{ \"type\":[\"AccessPolicy\"], \"action\":[\"read\"], \"assignee\":\""
                + bobDid + "\", \"target\":{ \"type\":\"StorageResource\", \"value\":[\"" + baseUrl + "/x/\"] } }] }";
        String requestId = create("/.lws/access-requests", request, bobToken);
        await(n -> n.is("AccessRequest") && n.is(requestId));
    }

    @Test
    void grantLinkedToARequestNotifiesTheRequestInbox() throws Exception {
        // Bob's request carries its inbox; the grant references the request and has no own inbox.
        String request = "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessRequest\"], \"storage\":\""
                + baseUrl + "/\", \"inbox\":\"" + inboxUrl + "\", \"access\":[{ \"type\":[\"AccessPolicy\"],"
                + " \"action\":[\"read\"], \"assignee\":\"" + bobDid + "\","
                + " \"target\":{ \"type\":\"StorageResource\", \"value\":[\"" + baseUrl + "/y/\"] } }] }";
        String requestId = create("/.lws/access-requests", request, bobToken);

        String grant = "{ \"@context\":\"https://www.w3.org/ns/lws/v1\", \"type\":[\"AccessGrant\"], \"storage\":\""
                + baseUrl + "/\", \"request\":\"" + requestId + "\", \"access\":[{ \"type\":[\"AccessPolicy\"],"
                + " \"action\":[\"read\"], \"assignee\":\"" + bobDid + "\","
                + " \"target\":{ \"type\":\"StorageResource\", \"value\":[\"" + baseUrl + "/y/\"] } }] }";
        String grantId = create("/.lws/access-grants", grant, ownerToken);
        await(n -> n.is("AccessGrant") && n.is(grantId));
    }

    // ----- helpers -----

    private static String create(String path, String body, String token) throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/lws+json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(201, r.statusCode(), path + " -> " + r.statusCode() + " " + r.body());
        return r.headers().firstValue("Location").orElseThrow();
    }

    private static Received await(Predicate<Received> match) throws InterruptedException {
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (System.nanoTime() < deadline) {
            for (Received r : received) {
                if (match.test(r)) {
                    return r;
                }
            }
            Thread.sleep(50);
        }
        fail("expected notification not delivered");
        return null;
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
