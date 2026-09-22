package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import com.sun.net.httpserver.HttpServer;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * Integration test for the full webhook-notification path: a subscription + a resource change
 * deliver a signed {@code lws:Notification} to a real HTTP inbox, and the RFC 9421 signature and
 * Content-Digest verify against the server's published JWKS key — i.e. exactly what a real
 * subscriber would check.
 *
 * @author Erich Bremer
 */
class WebhookDeliveryTest {

    /**
     * This class's data directory. Deleted on the way out where the platform allows it, and by the
     * next run's sweep where it does not — see {@link TestDirs}. It used to be a bare
     * {@code createTempDirectory} that nothing ever removed, and the leak once filled a disk.
     */
    private static final Path tempDir = TestDirs.create();

    private record Received(String method, String contentType, String contentDigest,
            String signatureInput, String signature, byte[] body) {
    }

    private static Server lws;
    private static LwsComponents components;
    private static HttpServer inbox;
    private static int inboxPort;
    private static String baseUrl;
    private static HttpClient http;
    private static String subscriberToken;

    private static final CountDownLatch delivered = new CountDownLatch(1);
    private static final AtomicReference<Received> received = new AtomicReference<>();

    @BeforeAll
    static void start() throws Exception {
        // inbox
        inbox = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        inboxPort = inbox.getAddress().getPort();
        inbox.createContext("/inbox", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            received.set(new Received(
                    exchange.getRequestMethod(),
                    exchange.getRequestHeaders().getFirst("Content-Type"),
                    exchange.getRequestHeaders().getFirst("Content-Digest"),
                    exchange.getRequestHeaders().getFirst("Signature-Input"),
                    exchange.getRequestHeaders().getFirst("Signature"),
                    body));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            delivered.countDown();
        });
        inbox.start();

        // LWS server (open mode so anonymous can create resources)
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        subscriberToken = DidKeyTool.mint(null, 3600, baseUrl).token();
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        // Open mode: this class asserts protocol behaviour, not authorization outcomes,
        // so it opts in to the development posture rather than configuring an owner.
        p.setProperty("lws.dev.open", "true");
        p.setProperty("lws.data-dir", tempDir.toString());
        p.setProperty("lws.webhook.max-attempts", "1");
        p.setProperty("lws.subscription.purge-interval-seconds", "0");
        // The inbox is on loopback, which the delivery policy blocks by default as an SSRF target.
        // Allowing it explicitly is what an operator would do to notify an internal endpoint.
        p.setProperty("lws.webhook.allowed-hosts", "localhost");
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
    void deliversSignedNotificationToInbox() throws Exception {
        // Subscribe to the whole storage, delivering to our inbox.
        String subscription = "{ \"type\":\"WebhookSubscription\", \"topic\":[\"" + baseUrl + "/\"],"
                + " \"inbox\":\"http://localhost:" + inboxPort + "/inbox\" }";
        HttpResponse<String> sub = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/.lws/subscriptions"))
                .header("Content-Type", "application/ld+json")
                .header("Authorization", "Bearer " + subscriberToken)
                .POST(HttpRequest.BodyPublishers.ofString(subscription)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(201, sub.statusCode());

        // A change under the subscribed container triggers a notification.
        HttpResponse<String> created = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/"))
                .header("Content-Type", "text/turtle").header("Slug", "thing")
                .POST(HttpRequest.BodyPublishers.ofString("<#it> <http://schema.org/name> \"x\" .")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(201, created.statusCode());
        String resourceIri = created.headers().firstValue("Location").orElseThrow();

        assertTrue(delivered.await(10, TimeUnit.SECONDS), "notification should be delivered to the inbox");
        Received r = received.get();

        // The envelope is the lws10-core Notification Data Model, delivered as application/lws+json
        // (lws10-notifications-webhook): a Notification naming the storage, wrapping one Create
        // activity about the new resource, with the container it was added to as `target`.
        assertEquals("POST", r.method());
        assertTrue(r.contentType().startsWith("application/lws+json"), r.contentType());
        String body = new String(r.body(), StandardCharsets.UTF_8);
        JsonObject envelope;
        try (JsonReader reader = Json.createReader(new StringReader(body))) {
            envelope = reader.readObject();
        }
        assertEquals(Json.createArrayBuilder().add("https://www.w3.org/ns/lws/v1")
                .add("https://www.w3.org/ns/activitystreams").build(), envelope.getJsonArray("@context"));
        assertEquals("Notification", envelope.getString("type"));
        assertEquals(baseUrl + "/", envelope.getString("storage"));
        JsonObject activity = envelope.getJsonObject("activity");
        assertEquals(Json.createArrayBuilder().add("Create").build(), activity.getJsonArray("type"));
        assertEquals(resourceIri, activity.getJsonObject("object").getString("id"));
        assertEquals(Json.createArrayBuilder().add("DataResource").build(),
                activity.getJsonObject("object").getJsonArray("type"));
        assertEquals(baseUrl + "/", activity.getString("target"));
        assertTrue(activity.containsKey("id") && activity.containsKey("published"), body);
        assertFalse(activity.containsKey("actor"), "the actor is omitted by default (lws10-core privacy)");

        // Content-Digest matches the body (RFC 9530).
        String expectedDigest = "sha-256=:" + Base64.getEncoder().encodeToString(sha256(r.body())) + ":";
        assertEquals(expectedDigest, r.contentDigest());

        // RFC 9421 signature, verified the way lws10-notifications-webhook tells a receiver to: the
        // keyid is a URL with a fragment; without the fragment it is the storage identifier, which
        // dereferences to the storage description; the key is the verification method whose id is
        // the keyid.
        assertTrue(r.signatureInput() != null && r.signature() != null, "signature headers present");
        String params = r.signatureInput().substring(r.signatureInput().indexOf('=') + 1);
        java.util.regex.Matcher keyid = java.util.regex.Pattern.compile("keyid=\"([^\"]+)\"").matcher(params);
        assertTrue(keyid.find(), params);
        byte[] publicKey = ed25519PublicKeyFromStorageDescription(keyid.group(1));
        String signatureBase = String.join("\n",
                "\"@method\": POST",
                "\"@scheme\": http",
                "\"@authority\": localhost:" + inboxPort,
                "\"@path\": /inbox",
                "\"content-type\": " + r.contentType(),
                "\"content-digest\": " + r.contentDigest(),
                "\"@signature-params\": " + params);
        String sigB64 = r.signature().substring(r.signature().indexOf(":") + 1, r.signature().lastIndexOf(":"));
        byte[] signature = Base64.getDecoder().decode(sigB64);

        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        byte[] baseBytes = signatureBase.getBytes(StandardCharsets.UTF_8);
        verifier.update(baseBytes, 0, baseBytes.length);
        assertTrue(verifier.verifySignature(signature), "DPoP-style HTTP Message Signature must verify");
    }

    /** The receiver's steps (lws10-notifications-webhook, Signature Verification), literally. */
    private static byte[] ed25519PublicKeyFromStorageDescription(String keyid) throws Exception {
        int hash = keyid.indexOf('#');
        assertTrue(hash > 0, "the keyid must be a URL with a fragment: " + keyid);
        String storage = keyid.substring(0, hash);
        assertEquals(baseUrl + "/", storage, "the fragment-less keyid is the storage identifier");
        HttpResponse<String> described = http.send(HttpRequest.newBuilder(URI.create(storage))
                .header("Accept", "application/lws+cid").build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, described.statusCode());
        try (JsonReader reader = Json.createReader(new StringReader(described.body()))) {
            JsonObject doc = reader.readObject();
            assertEquals(storage, doc.getString("id"), "the description's id matches the storage identifier");
            for (var method : doc.getJsonArray("verificationMethod")) {
                JsonObject vm = method.asJsonObject();
                if (vm.getString("id").equals(keyid)) {
                    assertTrue(doc.getJsonArray("authentication").toString().contains(keyid),
                            "referenced from authentication");
                    return Base64.getUrlDecoder().decode(vm.getJsonObject("publicKeyJwk").getString("x"));
                }
            }
        }
        throw new AssertionError("no verification method " + keyid + " in the storage description");
    }

    /**
     * The inbox URL is client-supplied, so it is checked against the delivery policy at creation
     * time. Only {@code localhost} is allow-listed here; {@code 127.0.0.1} resolves to loopback and
     * is not, so it is refused — the same check that stops an inbox aimed at a cloud-metadata or
     * internal address.
     */
    @Test
    void refusesAnInboxTheDeliveryPolicyBlocks() throws Exception {
        String subscription = "{ \"type\":\"WebhookSubscription\", \"topic\":[\"" + baseUrl + "/\"],"
                + " \"inbox\":\"http://127.0.0.1:" + inboxPort + "/inbox\" }";
        HttpResponse<String> sub = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/.lws/subscriptions"))
                .header("Content-Type", "application/ld+json")
                .header("Authorization", "Bearer " + subscriberToken)
                .POST(HttpRequest.BodyPublishers.ofString(subscription)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, sub.statusCode(), sub.body());
    }

    /** An unauthenticated subscriber cannot be quota-limited or manage what it created. */
    @Test
    void refusesAnonymousSubscriptionCreation() throws Exception {
        String subscription = "{ \"type\":\"WebhookSubscription\", \"topic\":[\"" + baseUrl + "/\"],"
                + " \"inbox\":\"http://localhost:" + inboxPort + "/inbox\" }";
        HttpResponse<String> sub = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/.lws/subscriptions"))
                .header("Content-Type", "application/ld+json")
                .POST(HttpRequest.BodyPublishers.ofString(subscription)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, sub.statusCode(), sub.body());
    }

    /**
     * Finding M37. This endpoint accepts a body before it has authorized anything, so it has to say
     * what it will accept up front rather than discover it in the parser.
     */
    @Test
    void refusesASubscriptionBodyThatDoesNotDeclareJson() throws Exception {
        String subscription = "{ \"type\":\"WebhookSubscription\", \"topic\":[\"" + baseUrl + "/\"],"
                + " \"inbox\":\"http://localhost:" + inboxPort + "/inbox\" }";
        HttpResponse<String> sub = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/.lws/subscriptions"))
                .header("Authorization", "Bearer " + subscriberToken)
                .header("Content-Type", "text/plain")
                .POST(HttpRequest.BodyPublishers.ofString(subscription)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(415, sub.statusCode(), sub.body());
    }

    /**
     * Finding M37. Every topic costs a read transaction at creation and a walk per resource event
     * afterwards, so the list an anonymous-capable endpoint accepts has to be bounded.
     */
    @Test
    void refusesASubscriptionDeclaringMoreTopicsThanAllowed() throws Exception {
        StringBuilder topics = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            topics.append(i == 0 ? "" : ",").append('"').append(baseUrl).append("/t").append(i).append('"');
        }
        String subscription = "{ \"type\":\"WebhookSubscription\", \"topic\":[" + topics + "],"
                + " \"inbox\":\"http://localhost:" + inboxPort + "/inbox\" }";
        HttpResponse<String> sub = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/.lws/subscriptions"))
                .header("Authorization", "Bearer " + subscriberToken)
                .header("Content-Type", "application/ld+json")
                .POST(HttpRequest.BodyPublishers.ofString(subscription)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, sub.statusCode(), sub.body());
    }

    /** Finding M17: a deeply nested body must not take the request thread down with an Error. */
    @Test
    void refusesADeeplyNestedSubscriptionBody() throws Exception {
        String deep = "[".repeat(4000) + "]".repeat(4000);
        HttpResponse<String> sub = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/.lws/subscriptions"))
                .header("Authorization", "Bearer " + subscriberToken)
                .header("Content-Type", "application/ld+json")
                .POST(HttpRequest.BodyPublishers.ofString(deep)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, sub.statusCode(), sub.body());
        assertTrue(sub.body().contains("nested deeper than"), sub.body());
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
