package com.ebremer.lws.server.notifications;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import com.sun.net.httpserver.HttpServer;
import jakarta.json.Json;
import jakarta.json.JsonReader;
import org.apache.jena.query.DatasetFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;

/**
 * The per-host in-flight cap limits concurrency without discarding work: deliveries to a host at
 * its cap wait their turn, within {@code lws.webhook.queue-capacity}. It used to drop them, so a
 * subscriber lost notifications whenever more than four were going to one host at once
 * (Touchstone webhook-signature-verifies, 2026-10-02).
 *
 * @author Erich Bremer
 */
class PerHostDeliveryLimitTest {

    private static final String BASE = "http://example.org";
    private static final String BOB = "https://bob.example/profile#me";

    private HttpServer inbox;
    private WebhookDispatcher dispatcher;

    @AfterEach
    void tearDown() {
        if (dispatcher != null) {
            dispatcher.close();
        }
        if (inbox != null) {
            inbox.stop(0);
        }
    }

    @Test
    void deliveriesBeyondTheCapWaitTheirTurnAndAllArrive(@TempDir Path dir) throws Exception {
        AtomicInteger concurrent = new AtomicInteger();
        AtomicInteger mostAtOnce = new AtomicInteger();
        AtomicInteger hits = new AtomicInteger();
        Subscription sub = setUp(dir, 2, 100, concurrent, mostAtOnce, hits, 150);

        for (int i = 0; i < 10; i++) {
            dispatcher.deliver(sub, ("{\"n\":" + i + "}").getBytes(StandardCharsets.UTF_8), "application/lws+json");
        }
        await(() -> hits.get() == 10);

        assertEquals(10, hits.get(), "no delivery may be dropped because its host was busy");
        assertTrue(mostAtOnce.get() <= 2, "the cap still bounds concurrency: " + mostAtOnce.get() + " at once");
        assertEquals(0, dispatcher.waitingCount());
    }

    @Test
    void theQueueCapacityStillBoundsWhatWaits(@TempDir Path dir) throws Exception {
        AtomicInteger concurrent = new AtomicInteger();
        AtomicInteger mostAtOnce = new AtomicInteger();
        AtomicInteger hits = new AtomicInteger();
        // one at a time to the host, three may wait: the rest of a burst of ten is dropped
        Subscription sub = setUp(dir, 1, 3, concurrent, mostAtOnce, hits, 400);

        for (int i = 0; i < 10; i++) {
            dispatcher.deliver(sub, ("{\"n\":" + i + "}").getBytes(StandardCharsets.UTF_8), "application/lws+json");
        }
        await(() -> hits.get() >= 4 && dispatcher.waitingCount() == 0);
        Thread.sleep(600);

        assertEquals(4, hits.get(), "one in flight and three waiting are delivered; the rest are dropped");
    }

    private Subscription setUp(Path dir, int maxInFlight, int capacity, AtomicInteger concurrent,
                               AtomicInteger mostAtOnce, AtomicInteger hits, long delayMillis) throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        inbox = HttpServer.create(new InetSocketAddress("localhost", port), 0);
        inbox.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        inbox.createContext("/hook", exchange -> {
            int now = concurrent.incrementAndGet();
            mostAtOnce.accumulateAndGet(now, Math::max);
            try {
                Thread.sleep(delayMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            concurrent.decrementAndGet();
            hits.incrementAndGet();
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
        });
        inbox.start();

        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.owners", BOB);
        p.setProperty("lws.data-dir", dir.toString());
        p.setProperty("lws.webhook.allowed-hosts", "localhost");
        p.setProperty("lws.webhook.max-attempts", "1");
        p.setProperty("lws.webhook.threads", "8");
        p.setProperty("lws.webhook.max-in-flight-per-host", String.valueOf(maxInFlight));
        p.setProperty("lws.webhook.queue-capacity", String.valueOf(capacity));
        p.setProperty("lws.webhook.max-consecutive-failures", "1000");
        LwsConfiguration config = LwsConfiguration.of(p);

        Tdb2RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        ResourceService rs = new ResourceService(store, new FileSystemBinaryStore(config.blobDir()),
                new ResourceRegistry(), (LwsPrincipal who, String iri, AclMode mode) -> true, config, Clock.systemUTC());
        rs.ensureStorageRoot();
        SubscriptionService subscriptions = new SubscriptionService(store, rs, config, Clock.systemUTC(),
                OutboundFetchPolicy.permitAll());
        dispatcher = new WebhookDispatcher(new WebhookKeys(config.dataDir().resolve("keys")),
                subscriptions, config, OutboundFetchPolicy.permitAll());
        try (JsonReader r = Json.createReader(new StringReader(
                "{\"type\":\"WebhookSubscription\",\"topic\":[\"" + BASE + "/\"],\"inbox\":\"http://localhost:"
                        + port + "/hook\"}"))) {
            return subscriptions.create(new LwsPrincipal(BOB, "iss", null), r.readObject());
        }
    }

    private static void await(java.util.function.BooleanSupplier done) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (!done.getAsBoolean() && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
    }
}
