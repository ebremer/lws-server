package com.ebremer.lws.server.notifications;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Properties;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.apache.jena.query.DatasetFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.TestDirs;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.DefaultAccessPolicy;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;
import com.ebremer.lws.server.auth.OwnerAuthorizer;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;

/**
 * Verifies that expired subscriptions are purged and live ones are kept.
 *
 * @author Erich Bremer
 */
class SubscriptionPurgeTest {

    /**
     * A fresh data directory per test. Deleted on the way out where the platform allows it, and by
     * the next run's sweep where it does not — see {@link TestDirs}.
     */
    private final Path tempDir = TestDirs.create();

    private static final String BASE = "http://localhost:8080";
    private static final String ROOT = BASE + "/";

    /** Creation happens at this instant; the purge below runs two minutes later. */
    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

    private SubscriptionService subscriptions;

    @BeforeEach
    void setUp() throws Exception {
        Tdb2RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        Path tmp = tempDir;
        FileSystemBinaryStore blobs = new FileSystemBinaryStore(tmp.resolve("blobs"));
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE); // no owners -> open mode, so the topic is readable
        // Open mode: this class asserts protocol behaviour, not authorization outcomes,
        // so it opts in to the development posture rather than configuring an owner.
        p.setProperty("lws.dev.open", "true");
        LwsConfiguration config = LwsConfiguration.of(p);
        ResourceRegistry registry = new ResourceRegistry();
        ResourceService resources = new ResourceService(store, blobs, registry,
                new OwnerAuthorizer(store, registry, new DefaultAccessPolicy(config)), config, Clock.systemUTC());
        resources.ensureStorageRoot();
        // permitAll: this unit test is about expiry, not delivery targets, and resolving the
        // example.org inboxes below would otherwise need DNS.
        subscriptions = new SubscriptionService(store, resources, config,
                Clock.fixed(T0, java.time.ZoneOffset.UTC), OutboundFetchPolicy.permitAll());
    }

    @Test
    void purgesOnlyExpiredSubscriptions() {
        // Short-lived: expires a minute after creation.
        JsonObject shortLivedReq = Json.createObjectBuilder()
                .add("type", "WebhookSubscription")
                .add("topic", Json.createArrayBuilder().add(ROOT))
                .add("inbox", "https://example.org/inbox")
                .add("expires", T0.plusSeconds(60).toString())
                .build();
        // No expiry requested: the server imposes lws.subscriptions.max-lifetime-seconds (30 days),
        // so this one is still live two minutes in.
        JsonObject liveReq = Json.createObjectBuilder()
                .add("type", "WebhookSubscription")
                .add("topic", Json.createArrayBuilder().add(ROOT))
                .add("inbox", "https://example.org/inbox2")
                .build();

        LwsPrincipal subscriber = new LwsPrincipal("https://alice.example/#me", null, null);
        Subscription expired = subscriptions.create(subscriber, shortLivedReq);
        Subscription live = subscriptions.create(subscriber, liveReq);
        assertEquals(2, subscriptions.all().size());
        assertNotNull(live.expires(), "an open-ended subscription is given a bounded lifetime");

        int purged = subscriptions.purgeExpired(T0.plusSeconds(120));

        assertEquals(1, purged);
        assertTrue(subscriptions.get(expired.id()).isEmpty(), "expired subscription should be gone");
        assertTrue(subscriptions.get(live.id()).isPresent(), "live subscription should remain");
    }
}
