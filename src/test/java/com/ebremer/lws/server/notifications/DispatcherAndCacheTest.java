package com.ebremer.lws.server.notifications;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import com.sun.net.httpserver.HttpServer;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdfconnection.RDFConnection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;

/**
 * How a delivery outcome is classified, how often the subscription graph is read, and who may list
 * subscriptions (findings M32, M34 and L39).
 *
 * @author Erich Bremer
 */
class DispatcherAndCacheTest {

    private static final String BASE = "http://example.org";
    private static final String ALICE = "https://alice.example/profile#me";
    private static final String BOB = "https://bob.example/profile#me";

    private final LwsPrincipal alice = new LwsPrincipal(ALICE, "iss", null);
    private final LwsPrincipal bob = new LwsPrincipal(BOB, "iss", null);

    private CountingStore store;
    private LwsConfiguration config;
    private SubscriptionService subscriptions;
    private HttpServer inbox;
    private WebhookDispatcher dispatcher;

    @BeforeEach
    void setUp(@TempDir Path dir) throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.owners", ALICE);
        p.setProperty("lws.data-dir", dir.toString());
        p.setProperty("lws.webhook.allowed-hosts", "localhost");
        p.setProperty("lws.webhook.max-attempts", "5");
        p.setProperty("lws.webhook.retry-backoff-ms", "10");
        p.setProperty("lws.webhook.max-consecutive-failures", "10");
        config = LwsConfiguration.of(p);

        store = new CountingStore(new Tdb2RdfStore(DatasetFactory.createTxnMem()));
        ResourceService rs = new ResourceService(store, new FileSystemBinaryStore(config.blobDir()),
                new ResourceRegistry(), DispatcherAndCacheTest::onlyAliceControls, config, Clock.systemUTC());
        rs.ensureStorageRoot();
        subscriptions = new SubscriptionService(store, rs, config, Clock.systemUTC(),
                OutboundFetchPolicy.permitAll());
    }

    @AfterEach
    void tearDown() {
        if (dispatcher != null) {
            dispatcher.close();
        }
        if (inbox != null) {
            inbox.stop(0);
        }
    }

    /** Everyone may read and write; only the configured owner controls the storage. */
    private static boolean onlyAliceControls(LwsPrincipal principal, String iri, AclMode mode) {
        return mode != AclMode.CONTROL || (principal != null && ALICE.equals(principal.webId()));
    }

    // ----- M34: outcomes are classified, not retried blindly -----

    @Test
    void statusCodesAreClassifiedByWhetherRetryingCouldEverHelp() {
        assertEquals(DeliveryOutcome.DELIVERED, DeliveryOutcome.forStatus(200));
        assertEquals(DeliveryOutcome.DELIVERED, DeliveryOutcome.forStatus(204));
        assertEquals(DeliveryOutcome.GONE, DeliveryOutcome.forStatus(410));
        assertEquals(DeliveryOutcome.RETRY, DeliveryOutcome.forStatus(429));
        assertEquals(DeliveryOutcome.RETRY, DeliveryOutcome.forStatus(503));
        assertEquals(DeliveryOutcome.RETRY, DeliveryOutcome.forStatus(500));
        assertEquals(DeliveryOutcome.PERMANENT, DeliveryOutcome.forStatus(404));
        assertEquals(DeliveryOutcome.PERMANENT, DeliveryOutcome.forStatus(400));
        assertEquals(DeliveryOutcome.PERMANENT, DeliveryOutcome.forStatus(403));

        assertTrue(DeliveryOutcome.RETRY.isRetryable());
        assertFalse(DeliveryOutcome.PERMANENT.isRetryable());
        assertFalse(DeliveryOutcome.GONE.isRetryable());
        assertTrue(DeliveryOutcome.GONE.shouldDeactivate());
    }

    /** A 404 inbox is attempted once. It used to be attempted {@code max-attempts} times. */
    @Test
    void aPermanentFailureIsNotRetried() throws Exception {
        AtomicInteger hits = startInbox(exchange -> 404);
        Subscription sub = subscribe();

        dispatcher.deliver(sub, "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8), "application/ld+json");
        settle();

        assertEquals(1, hits.get(), "a 404 cannot become a 200 by asking again");
    }

    /** A 503 is transient, so the configured attempts are used. */
    @Test
    void aTransientFailureIsRetried() throws Exception {
        AtomicInteger hits = startInbox(exchange -> 503);
        Subscription sub = subscribe();

        dispatcher.deliver(sub, "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8), "application/ld+json");
        settle();

        assertEquals(config.webhookMaxAttempts(), hits.get());
    }

    /** 410 Gone deactivates at once, rather than after ten consecutive failures. */
    @Test
    void goneDeactivatesTheSubscriptionImmediately() throws Exception {
        AtomicInteger hits = startInbox(exchange -> 410);
        Subscription sub = subscribe();

        dispatcher.deliver(sub, "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8), "application/ld+json");
        settle();

        assertEquals(1, hits.get(), "410 is final");
        assertFalse(subscriptions.get(sub.id()).orElseThrow().active(),
                "the subscriber said this inbox is finished; believe it");
    }

    // ----- M32: the subscription graph is not re-read per event -----

    @Test
    void repeatedMatchingDoesNotReReadTheSubscriptionGraph() {
        subscribe();
        subscriptions.all();                      // prime
        int before = store.reads.get();

        for (int i = 0; i < 50; i++) {
            subscriptions.activeMatching(BASE + "/some/resource-" + i);
        }

        assertEquals(before, store.reads.get(),
                "matching used to fetch and re-parse the whole subscription graph per event, "
                        + "on the writer's request thread");
    }

    @Test
    void theSnapshotIsSharedButInvalidatedByEveryMutation() {
        subscribe();
        List<Subscription> first = subscriptions.all();
        assertSame(first, subscriptions.all(), "an unchanged store hands back the same snapshot");

        Subscription second = subscribe();
        assertEquals(2, subscriptions.all().size(), "a create must be visible immediately");

        subscriptions.delete(second.id());
        assertEquals(1, subscriptions.all().size(), "and so must a delete");

        subscriptions.deactivate(subscriptions.all().get(0).id());
        assertFalse(subscriptions.all().get(0).active(), "and a deactivation");
    }

    // ----- L39: who may list subscriptions -----

    @Test
    void listingSubscriptionsRequiresAuthenticationAndShowsOnlyYourOwn() {
        Subscription mine = subscriptions.create(bob, subscriptionJson());
        subscriptions.create(alice, subscriptionJson());

        LwsException anonymous = assertThrows(LwsException.class, () -> subscriptions.listVisibleTo(null));
        assertEquals(401, anonymous.status());

        List<Subscription> bobsView = subscriptions.listVisibleTo(bob);
        assertEquals(List.of(mine.id()), bobsView.stream().map(Subscription::id).toList(),
                "a subscriber sees its own subscriptions and no one else's");

        // Alice is the configured owner, so she controls the storage and sees all of them.
        assertEquals(2, subscriptions.listVisibleTo(alice).size());
    }

    // ----- helpers -----

    private Subscription subscribe() {
        return subscriptions.create(bob, subscriptionJson());
    }

    private JsonObject subscriptionJson() {
        String inboxUrl = inbox == null ? "http://localhost:1/hook"
                : "http://localhost:" + inbox.getAddress().getPort() + "/hook";
        try (JsonReader r = Json.createReader(new StringReader(
                "{\"type\":\"WebhookSubscription\",\"topic\":[\"" + BASE + "/\"],\"inbox\":\""
                        + inboxUrl + "\"}"))) {
            return r.readObject();
        }
    }

    /** A local inbox answering a fixed status, counting how many times it was asked. */
    private AtomicInteger startInbox(Function<Object, Integer> status) throws Exception {
        AtomicInteger hits = new AtomicInteger();
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        inbox = HttpServer.create(new InetSocketAddress("localhost", port), 0);
        inbox.createContext("/hook", exchange -> {
            hits.incrementAndGet();
            exchange.sendResponseHeaders(status.apply(exchange), -1);
            exchange.close();
        });
        inbox.start();
        dispatcher = new WebhookDispatcher(new WebhookKeys(config.dataDir().resolve("keys")),
                subscriptions, config, OutboundFetchPolicy.permitAll());
        return hits;
    }

    /** Wait for the dispatcher's attempts (and any scheduled retries) to run out. */
    private void settle() throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        int stable = 0;
        int last = -1;
        while (System.nanoTime() < deadline && stable < 12) {
            Thread.sleep(25);
            int now = store.writes.get();
            stable = (now == last) ? stable + 1 : 0;
            last = now;
        }
    }

    /** Counts the units of work reaching the store, so "is this on the hot path?" is measurable. */
    private static final class CountingStore implements RdfStore {
        private final RdfStore delegate;
        private final AtomicInteger reads = new AtomicInteger();
        private final AtomicInteger writes = new AtomicInteger();

        CountingStore(RdfStore delegate) {
            this.delegate = delegate;
        }

        @Override
        public <T> T read(Function<RDFConnection, T> action) {
            reads.incrementAndGet();
            return delegate.read(action);
        }

        @Override
        public <T> T write(Function<RDFConnection, T> action) {
            writes.incrementAndGet();
            return delegate.write(action);
        }

        @Override
        public void readDo(Consumer<RDFConnection> action) {
            reads.incrementAndGet();
            delegate.readDo(action);
        }

        @Override
        public void writeDo(Consumer<RDFConnection> action) {
            writes.incrementAndGet();
            delegate.writeDo(action);
        }

        @Override
        public boolean inUnitOfWork() {
            return delegate.inUnitOfWork();
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}
