package com.ebremer.lws.server.notifications;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.DefaultAccessPolicy;
import com.ebremer.lws.server.auth.OwnerAuthorizer;
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

    private static final String BASE = "http://localhost:8080";
    private static final String ROOT = BASE + "/";

    private SubscriptionService subscriptions;

    @BeforeEach
    void setUp() throws Exception {
        Tdb2RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        Path tmp = Files.createTempDirectory("lws-sub-test");
        FileSystemBinaryStore blobs = new FileSystemBinaryStore(tmp.resolve("blobs"));
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE); // no owners -> open mode, so anonymous can subscribe
        LwsConfiguration config = LwsConfiguration.of(p);
        ResourceRegistry registry = new ResourceRegistry();
        ResourceService resources = new ResourceService(store, blobs, registry,
                new OwnerAuthorizer(store, registry, new DefaultAccessPolicy(config)), config, Clock.systemUTC());
        resources.ensureStorageRoot();
        subscriptions = new SubscriptionService(store, resources, config, Clock.systemUTC());
    }

    @Test
    void purgesOnlyExpiredSubscriptions() {
        JsonObject expiredReq = Json.createObjectBuilder()
                .add("type", "WebhookSubscription")
                .add("topic", Json.createArrayBuilder().add(ROOT))
                .add("inbox", "https://example.org/inbox")
                .add("expires", Instant.now().minusSeconds(3600).toString())
                .build();
        JsonObject liveReq = Json.createObjectBuilder()
                .add("type", "WebhookSubscription")
                .add("topic", Json.createArrayBuilder().add(ROOT))
                .add("inbox", "https://example.org/inbox2")
                .build(); // no expiry

        Subscription expired = subscriptions.create(null, expiredReq);
        Subscription live = subscriptions.create(null, liveReq);
        assertEquals(2, subscriptions.all().size());

        int purged = subscriptions.purgeExpired(Instant.now());

        assertEquals(1, purged);
        assertTrue(subscriptions.get(expired.id()).isEmpty(), "expired subscription should be gone");
        assertTrue(subscriptions.get(live.id()).isPresent(), "live subscription should remain");
    }
}
