package com.ebremer.lws.server.notifications;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import com.sun.net.httpserver.HttpServer;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;
import com.ebremer.lws.server.auth.WacAclService;
import com.ebremer.lws.server.core.IfMatch;
import com.ebremer.lws.server.core.LinksetService;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.core.ResourceService.TypeHint;
import com.ebremer.lws.server.core.ResourceService.WriteRequest;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;
import com.ebremer.lws.server.vocab.ACL;

/**
 * What a move tells the subscribers (lws10-core, Notifications and Moving Resources): one
 * {@code Move} naming both containers, for a subscriber who may read the resource where it went;
 * a {@code Delete} of the previous IRI for one who could read it only where it was; nothing for
 * anyone else. Delivered to a real inbox, as a subscriber would receive it.
 *
 * @author Erich Bremer
 */
class MoveNotificationTest {

    private static final String BASE = "http://example.org";
    private static final String ALICE = "https://alice.example/profile#me";
    private static final String MALLORY = "https://mallory.example/profile#me";

    private final LwsPrincipal alice = new LwsPrincipal(ALICE, "iss", null);
    private final LwsPrincipal mallory = new LwsPrincipal(MALLORY, "iss", null);

    private HttpServer inbox;
    private String inboxBase;
    private final Map<String, List<JsonObject>> received = new ConcurrentHashMap<>();
    private SubscriptionService subscriptions;
    private WebhookDispatcher dispatcher;
    private ResourceService rs;
    private LinksetService linksets;

    @BeforeEach
    void setUp(@TempDir Path dir) throws Exception {
        inbox = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        inbox.createContext("/", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            try (JsonReader r = Json.createReader(new StringReader(new String(body, StandardCharsets.UTF_8)))) {
                received.computeIfAbsent(exchange.getRequestURI().getPath(), k -> new CopyOnWriteArrayList<>())
                        .add(r.readObject());
            }
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        inbox.start();
        inboxBase = "http://localhost:" + inbox.getAddress().getPort();

        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.access-control", "wac");
        p.setProperty("lws.owners", ALICE);
        p.setProperty("lws.data-dir", dir.toString());
        p.setProperty("lws.webhook.max-attempts", "1");
        LwsConfiguration config = LwsConfiguration.of(p);

        Tdb2RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        WacAclService wac = new WacAclService(store, config);
        rs = new ResourceService(store, new FileSystemBinaryStore(config.blobDir()),
                new ResourceRegistry(), wac, config, Clock.systemUTC());
        rs.ensureStorageRoot();
        wac.bootstrapRootAcl();
        rs.addDeleteCleanup(wac);
        rs.addRelocation(wac);
        linksets = new LinksetService(store, rs, config);
        rs.addDeleteCleanup(linksets);
        rs.addRelocation(linksets);

        OutboundFetchPolicy anywhere = OutboundFetchPolicy.permitAll();
        subscriptions = new SubscriptionService(store, rs, config, Clock.systemUTC(), anywhere);
        dispatcher = new WebhookDispatcher(new WebhookKeys(dir.resolve("keys")), subscriptions, config, anywhere);
        NotificationEmitter emitter = new NotificationEmitter(subscriptions, dispatcher, rs, config);
        rs.addEventListener(emitter);
        rs.setDeleteAudience(emitter::subscribersAllowedToKnow);

        // Mallory may read /data/ and, through it, /data/src/; /data/dst/ has an ACL of its own
        // that admits Alice only.
        rs.put("/data/", alice, container());
        rs.put("/data/src/", alice, container());
        rs.put("/data/dst/", alice, container());
        rs.put("/data/src/note", alice, text("a resource on the move"));
        wac.putSystemAclFor(BASE + "/data/", acl(BASE + "/data/", grant(ALICE, ACL.Read, ACL.Write, ACL.Control),
                grant(MALLORY, ACL.Read)));
        wac.putSystemAclFor(BASE + "/data/dst/", acl(BASE + "/data/dst/",
                grant(ALICE, ACL.Read, ACL.Write, ACL.Control)));
    }

    @AfterEach
    void tearDown() {
        dispatcher.close();
        inbox.stop(0);
    }

    @Test
    void aSubscriberWhoMayFollowTheResourceHearsOneMoveFromOneContainerToTheOther() throws Exception {
        subscribe(alice, BASE + "/data/", "/alice");

        move("/data/src/note", BASE + "/data/dst/");

        JsonObject activity = only("/alice");
        assertEquals("Move", activity.getJsonArray("type").getString(0));
        assertEquals(BASE + "/data/src/", activity.getString("origin"), "the container it was removed from");
        assertEquals(BASE + "/data/dst/", activity.getString("target"), "the container it was added to");
        JsonObject object = activity.getJsonObject("object");
        assertEquals(BASE + "/data/dst/note", object.getString("id"), "the resource as it is after the move");
        assertEquals("DataResource", object.getJsonArray("type").getString(0));
    }

    /** A subscription to the resource itself names its previous IRI, and still hears the move. */
    @Test
    void aSubscriptionToThePreviousIriHearsTheMoveToo() throws Exception {
        subscribe(alice, BASE + "/data/src/note", "/alice");

        move("/data/src/note", BASE + "/data/dst/");

        assertEquals("Move", only("/alice").getJsonArray("type").getString(0));
    }

    /**
     * Mallory could read the resource where it was and may not read it where it went. To her it
     * left, and she must not learn where to: a Delete of the previous IRI, from the container it
     * left, and no Move.
     */
    @Test
    void aSubscriberWhoMayNotFollowItIsToldItLeftAndNotWhereItWent() throws Exception {
        subscribe(alice, BASE + "/data/", "/alice");
        subscribe(mallory, BASE + "/data/", "/mallory");

        move("/data/src/note", BASE + "/data/dst/");

        only("/alice");
        JsonObject activity = only("/mallory");
        assertEquals("Delete", activity.getJsonArray("type").getString(0));
        assertEquals(BASE + "/data/src/note", activity.getJsonObject("object").getString("id"));
        assertEquals(BASE + "/data/src/", activity.getString("origin"));
        assertTrue(!activity.containsKey("target") && !activity.toString().contains("/data/dst/"),
                "nothing about where it went: " + activity);
    }

    /** One who could read it in neither place is told nothing at all. */
    @Test
    void aSubscriberWhoCouldReadItNowhereIsToldNothing() throws Exception {
        rs.put("/data/dst/inner/", alice, container());
        rs.put("/data/dst/inner/private", alice, text("alice's"));
        subscribe(alice, BASE + "/data/", "/alice");
        subscribe(mallory, BASE + "/data/", "/mallory");

        move("/data/dst/inner/private", BASE + "/data/dst/");

        only("/alice");
        Thread.sleep(500); // deliveries are queued together; give a wrong one the time to arrive
        assertEquals(List.of(), received.getOrDefault("/mallory", List.of()));
    }

    /** A moved container is one activity: its members moved with it and raise none of their own. */
    @Test
    void aMovedContainerIsOneActivity() throws Exception {
        rs.put("/data/src/sub/", alice, container());
        rs.put("/data/src/sub/a", alice, text("a"));
        rs.put("/data/src/sub/b", alice, text("b"));
        subscribe(alice, BASE + "/data/", "/alice");

        move("/data/src/sub/", BASE + "/data/dst/");

        JsonObject activity = only("/alice");
        assertEquals("Move", activity.getJsonArray("type").getString(0));
        assertEquals(BASE + "/data/dst/sub/", activity.getJsonObject("object").getString("id"));
        assertEquals("Container", activity.getJsonObject("object").getJsonArray("type").getString(0));
        Thread.sleep(500);
        assertEquals(1, received.get("/alice").size(), "exactly one notification: " + received.get("/alice"));
    }

    // ----- helpers -----

    private void move(String path, String destination) {
        linksets.jsonPatch(path, ("[{\"op\":\"replace\",\"path\":\"/linkset/0/up/0/href\",\"value\":\""
                + destination + "\"}]").getBytes(StandardCharsets.UTF_8), IfMatch.NONE, alice);
    }

    /** The activity of the one notification an inbox path receives, waiting for it to arrive. */
    private JsonObject only(String path) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (received.getOrDefault(path, List.of()).isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.sleep(25);
        }
        List<JsonObject> notifications = received.getOrDefault(path, List.of());
        assertEquals(1, notifications.size(), path + ": " + notifications);
        assertEquals("Notification", notifications.get(0).getString("type"));
        return notifications.get(0).getJsonObject("activity");
    }

    private void subscribe(LwsPrincipal who, String topic, String inboxPath) {
        JsonObject request;
        try (JsonReader r = Json.createReader(new StringReader("{\"type\":\"WebhookSubscription\",\"topic\":[\""
                + topic + "\"],\"inbox\":\"" + inboxBase + inboxPath + "\"}"))) {
            request = r.readObject();
        }
        subscriptions.create(who, request);
    }

    private record Grant(String webId, Resource[] modes) {
    }

    private static Grant grant(String webId, Resource... modes) {
        return new Grant(webId, modes);
    }

    /** An ACL for a container, granting each agent its modes on it and on everything in it. */
    private static Model acl(String target, Grant... grants) {
        Model m = ModelFactory.createDefaultModel();
        for (Grant g : grants) {
            Resource a = m.createResource();
            a.addProperty(RDF.type, ACL.Authorization);
            a.addProperty(ACL.accessTo, m.createResource(target));
            a.addProperty(ACL.defaultAccess, m.createResource(target));
            a.addProperty(ACL.agent, m.createResource(g.webId()));
            for (Resource mode : g.modes()) {
                a.addProperty(ACL.mode, mode);
            }
        }
        return m;
    }

    private static WriteRequest text(String body) {
        return new WriteRequest("text/plain", body.getBytes(StandardCharsets.UTF_8), TypeHint.AUTO, null);
    }

    private static WriteRequest container() {
        return new WriteRequest(null, new byte[0], TypeHint.CONTAINER, null);
    }
}
