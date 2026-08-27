package com.ebremer.lws.server.notifications;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
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
import com.ebremer.lws.server.core.ActivityKind;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.RequestContext;
import com.ebremer.lws.server.core.ResourceEvent;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.core.ResourceService.TypeHint;
import com.ebremer.lws.server.core.ResourceService.WriteRequest;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;
import com.ebremer.lws.server.vocab.ACL;

/**
 * What a subscriber is told, and what decides it (findings H19 and M31).
 *
 * <p>Both findings are the same mistake seen from two sides: the decision about whether a
 * <em>subscriber</em> may hear about a change was being made from information that had nothing to do
 * with the subscriber — the deleted resource's parent container in one case, and the headers of
 * whoever happened to make the change in the other.
 *
 * @author Erich Bremer
 */
class NotificationAuthorizationTest {

    private static final String BASE = "http://example.org";
    private static final String ALICE = "https://alice.example/profile#me";
    private static final String MALLORY = "https://mallory.example/profile#me";
    private static final String APP = "https://app.example";

    private final LwsPrincipal alice = new LwsPrincipal(ALICE, "iss", null);
    private final LwsPrincipal mallory = new LwsPrincipal(MALLORY, "iss", null);

    private LwsConfiguration config;
    private WacAclService wac;
    private ResourceService rs;
    private SubscriptionService subscriptions;
    private NotificationEmitter emitter;
    private final List<ResourceEvent> emitted = new ArrayList<>();

    @BeforeEach
    void setUp(@TempDir Path dir) throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.access-control", "wac");
        p.setProperty("lws.owners", ALICE);
        p.setProperty("lws.data-dir", dir.toString());
        config = LwsConfiguration.of(p);

        Tdb2RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        wac = new WacAclService(store, config);
        rs = new ResourceService(store, new FileSystemBinaryStore(config.blobDir()),
                new ResourceRegistry(), wac, config, Clock.systemUTC());
        rs.ensureStorageRoot();
        wac.bootstrapRootAcl();
        rs.addDeleteCleanup(wac);

        OutboundFetchPolicy anywhere = OutboundFetchPolicy.permitAll();
        subscriptions = new SubscriptionService(store, rs, config, Clock.systemUTC(), anywhere);
        emitter = new NotificationEmitter(subscriptions,
                new WebhookDispatcher(new WebhookKeys(dir.resolve("keys")), subscriptions, config, anywhere),
                rs, config);
        rs.setDeleteAudience(emitter::subscribersAllowedToKnow);
        rs.addEventListener(emitted::add);

        // /data/ is readable by Mallory; /data/private carries its own ACL that is not.
        rs.put("/data/", alice, container());
        rs.put("/data/private", alice, rdf("secret"));
        wac.putSystemAclFor(BASE + "/data/", acl(BASE + "/data/", true,
                grant(ALICE, ACL.Read, ACL.Write, ACL.Control), grant(MALLORY, ACL.Read)));
        wac.putSystemAclFor(BASE + "/data/private", acl(BASE + "/data/private", false,
                grant(ALICE, ACL.Read, ACL.Write, ACL.Control)));
    }

    @AfterEach
    void clearContext() {
        RequestContext.clear();
    }

    // ----- H19 -----

    @Test
    void aSubscriberWhoCanOnlyReadTheParentIsNotToldAboutAPrivateChild() {
        String subscription = subscribe(mallory, BASE + "/data/");
        String alicesSubscription = subscribe(alice, BASE + "/data/");

        // While it still exists, the decision is already the right one.
        Set<String> allowed = emitter.subscribersAllowedToKnow(BASE + "/data/private");
        assertFalse(allowed.contains(subscription),
                "Mallory can read /data/ but not /data/private, and a delete must not tell her it existed");
        assertTrue(allowed.contains(alicesSubscription));

        emitted.clear();
        rs.delete("/data/private", alice, false, com.ebremer.lws.server.core.IfMatch.NONE);

        ResourceEvent event = onlyDelete();
        assertFalse(event.audience().contains(subscription),
                "the captured audience is what decides delivery, and it must exclude her: " + event.audience());
        assertTrue(event.audience().contains(alicesSubscription));
    }

    /**
     * The capture has to happen before the transaction, because the resource's own ACL is erased
     * inside it (H24). Asking afterwards resolves through the parent and readmits exactly the
     * subscriber the child's ACL excluded — so this asserts the answer survives the delete.
     */
    @Test
    void theDecisionSurvivesTheAclBeingErasedWithTheResource() {
        String subscription = subscribe(mallory, BASE + "/data/");
        emitted.clear();

        rs.delete("/data/private", alice, false, com.ebremer.lws.server.core.IfMatch.NONE);

        assertTrue(wac.getAclModel(BASE + "/data/private").isEmpty(),
                "the child's ACL is gone by now — which is exactly why the answer had to be captured");
        assertFalse(onlyDelete().audience().contains(subscription));
    }

    @Test
    void everyMemberOfARecursiveDeleteGetsItsOwnAudience() {
        rs.put("/data/open", alice, rdf("public"));
        wac.putSystemAclFor(BASE + "/data/open", acl(BASE + "/data/open", false,
                grant(ALICE, ACL.Read, ACL.Write, ACL.Control), grant(MALLORY, ACL.Read)));
        String subscription = subscribe(mallory, BASE + "/data/");
        emitted.clear();

        rs.delete("/data/", alice, true, com.ebremer.lws.server.core.IfMatch.NONE);

        ResourceEvent priv = deleteOf(BASE + "/data/private");
        ResourceEvent open = deleteOf(BASE + "/data/open");
        assertFalse(priv.audience().contains(subscription), "the private child stays private");
        assertTrue(open.audience().contains(subscription), "the readable one is still delivered");
    }

    /** A create or update authorizes against the resource itself, which is still there. */
    @Test
    void nonDeleteEventsCarryNoCapturedAudience() {
        emitted.clear();
        rs.put("/data/another", alice, rdf("v1"));
        assertNull(emitted.get(emitted.size() - 1).audience());
    }

    // ----- M31 -----

    /**
     * An {@code acl:origin} rule scopes access to a browser app. A webhook delivery is not that
     * request, so the writer's {@code Origin} must not decide it — yet the emitter runs on the
     * writer's thread, where {@link RequestContext} still holds the writer's headers.
     */
    @Test
    void theWritersOriginDoesNotDecideWhatASubscriberMayReceive() {
        wac.putSystemAclFor(BASE + "/data/private", acl(BASE + "/data/private", false,
                grant(ALICE, ACL.Read, ACL.Write, ACL.Control), originScoped(MALLORY, APP)));
        String subscription = subscribe(mallory, BASE + "/data/");

        // Mallory's grant applies only to requests from the app...
        RequestContext.setOrigin(APP);
        try {
            assertFalse(emitter.subscribersAllowedToKnow(BASE + "/data/private").contains(subscription),
                    "a write that happens to come from the allow-listed app must not widen a "
                            + "subscriber's access — the subscriber is not that app");
        } finally {
            RequestContext.clear();
        }
    }

    @Test
    void theWritersContextIsRestoredAfterwards() {
        subscribe(mallory, BASE + "/data/");
        RequestContext.setOrigin(APP);
        RequestContext.setPurposes(Set.of("urn:purpose:research"));

        emitter.subscribersAllowedToKnow(BASE + "/data/private");

        assertEquals(APP, RequestContext.origin(), "the request in progress still owns its context");
        assertEquals(Set.of("urn:purpose:research"), RequestContext.purposes());
    }

    // ----- helpers -----

    private ResourceEvent onlyDelete() {
        List<ResourceEvent> deletes = emitted.stream().filter(e -> e.kind() == ActivityKind.DELETE).toList();
        assertEquals(1, deletes.size(), "expected exactly one delete event: " + emitted);
        return deletes.get(0);
    }

    private ResourceEvent deleteOf(String iri) {
        return emitted.stream()
                .filter(e -> e.kind() == ActivityKind.DELETE && e.iri().equals(iri))
                .findFirst().orElseThrow(() -> new AssertionError("no delete event for " + iri));
    }

    private String subscribe(LwsPrincipal who, String topic) {
        JsonObject request = parse("{\"type\":\"WebhookSubscription\",\"topic\":[\"" + topic
                + "\"],\"inbox\":\"https://inbox.example/hook\"}");
        return subscriptions.create(who, request).id();
    }

    private static JsonObject parse(String json) {
        try (JsonReader r = Json.createReader(new StringReader(json))) {
            return r.readObject();
        }
    }

    // A small builder: each grant() call adds one acl:Authorization to a shared model.
    private record Grant(String webId, Resource[] modes, String origin) {
    }

    private static Grant grant(String webId, Resource... modes) {
        return new Grant(webId, modes, null);
    }

    private static Grant originScoped(String webId, String origin) {
        return new Grant(webId, new Resource[] {ACL.Read}, origin);
    }

    private static Model acl(String target, boolean alsoDefault, Grant... grants) {
        Model m = ModelFactory.createDefaultModel();
        for (Grant g : grants) {
            Resource a = m.createResource();
            a.addProperty(RDF.type, ACL.Authorization);
            a.addProperty(ACL.accessTo, m.createResource(target));
            if (alsoDefault) {
                a.addProperty(ACL.defaultAccess, m.createResource(target));
            }
            a.addProperty(ACL.agent, m.createResource(g.webId()));
            for (Resource mode : g.modes()) {
                a.addProperty(ACL.mode, mode);
            }
            if (g.origin() != null) {
                a.addProperty(ACL.origin, m.createResource(g.origin()));
            }
        }
        return m;
    }

    private static WriteRequest rdf(String name) {
        return new WriteRequest("text/turtle",
                ("<#it> <http://schema.org/name> \"" + name + "\" .").getBytes(StandardCharsets.UTF_8),
                TypeHint.RDF_SOURCE, null);
    }

    private static WriteRequest container() {
        return new WriteRequest(null, new byte[0], TypeHint.CONTAINER, null);
    }
}
