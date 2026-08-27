package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
 * A subscription's {@code inbox} is a URL the client picks and the server later POSTs to, signed.
 * Left unchecked that makes the storage an authenticated request-forgery primitive aimed wherever
 * the client can reach — cloud metadata first of all — and the delivery bookkeeping turns it into a
 * readable probe of the network the server sits in.
 *
 * <p>{@code OutboundFetchPolicy} refuses those addresses, and {@code SubscriptionService} applies it
 * at <em>creation</em> rather than at delivery, so the answer is a {@code 400} the client can act on
 * instead of a silent failure discovered later. This class pins that over real HTTP, and pins the
 * half that matters more than the status code: <strong>nothing is created</strong>. A subscription
 * stored and then never delivered to would still be a stored, attacker-chosen URL.
 *
 * <p>The redirect case from the same finding — a public host redirecting to a private one — is
 * covered at the unit level by {@code auth/HttpDocumentLoaderTest}, which is where the manual
 * hop-by-hop re-check lives.
 *
 * @author Erich Bremer
 */
class InboxSsrfTest {

    /** See {@link TestDirs}: {@code @TempDir} cannot be used with a memory-mapped TDB2 dataset. */
    private static final Path tempDir = TestDirs.create();

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;
    private static String token;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        DidKeyTool.Minted subscriber = DidKeyTool.mint(null, 3600, baseUrl);
        token = subscriber.token();
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.data-dir", tempDir.toString());
        p.setProperty("lws.owners", subscriber.did());
        // No lws.webhook.allowed-hosts: the DEFAULT posture is what an operator gets, and it is the
        // posture the guard has to hold in.
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
    void anInboxAtAnAddressThePolicyRefusesIsRejectedAndNothingIsCreated() throws Exception {
        String[] refused = {
            "http://169.254.169.254/latest/meta-data/",   // cloud metadata, the classic target
            "http://10.0.0.1/inbox",                      // RFC 1918
            "http://127.0.0.1/inbox",                     // loopback
            "http://100.64.0.1/inbox",                    // carrier-grade NAT
            "http://[::ffff:169.254.169.254]/inbox",      // the same metadata host, IPv6-wrapped
            "file:///etc/passwd",                         // not even http
            "http://[2002:a9fe:a9fe::1]/inbox",           // ...and 6to4-wrapped
        };
        String before = list();
        for (String inbox : refused) {
            HttpResponse<String> r = subscribe(inbox);
            assertEquals(400, r.statusCode(), () -> "inbox " + inbox + " was not refused");
            assertTrue(r.body().contains("not an acceptable delivery target"),
                    () -> "refused for the wrong reason: " + r.body());
            assertTrue(r.headers().firstValue("Location").isEmpty(),
                    () -> "a refused subscription still got a Location: " + inbox);
        }
        // The assertion that carries the meaning, and the reason it compares the whole listing
        // rather than searching for each URL: a stored subscription the server merely never
        // delivers to is still a stored, attacker-chosen URL.
        assertEquals(before, list(), "a refused subscription was stored anyway");
    }

    /** The control: without it, the test above would pass against a server that refused everything. */
    @Test
    void anInboxOnAPermittedHostIsStillAccepted() throws Exception {
        // An IP literal rather than a name: the policy resolves the host, and it fails CLOSED on a
        // name that does not resolve — so a documentation hostname would be refused for a reason
        // that has nothing to do with the address being private, and this control would prove
        // nothing. Never actually connected to: delivery only happens when a named resource changes.
        HttpResponse<String> r = subscribe("https://8.8.8.8/notify");
        assertEquals(201, r.statusCode(), r.body());
        String location = r.headers().firstValue("Location").orElse(null);
        assertNotNull(location, "an accepted subscription must carry a Location");
        // The listing withholds the inbox itself (it would make delivery a readable probe of our
        // network), so the subscription's own IRI is what proves it was stored.
        assertTrue(list().contains(location), "the accepted subscription was not stored");
    }

    private static HttpResponse<String> subscribe(String inbox) throws Exception {
        String body = "{\"type\":\"WebhookSubscription\",\"topic\":\"" + baseUrl + "/\","
                + "\"inbox\":\"" + inbox + "\"}";
        return send("POST", "/.lws/subscriptions", body, "Content-Type", "application/lws+json");
    }

    private static String list() throws Exception {
        return send("GET", "/.lws/subscriptions", null, "Accept", "text/turtle").body();
    }

    private static HttpResponse<String> send(String method, String path, String body, String... headers)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + token);
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        b.method(method, body == null
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
