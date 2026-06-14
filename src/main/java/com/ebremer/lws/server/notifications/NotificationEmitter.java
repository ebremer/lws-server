package com.ebremer.lws.server.notifications;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.Iris;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.ResourceEvent;
import com.ebremer.lws.server.core.ResourceEventListener;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.core.ResourceType;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Turns {@link ResourceEvent}s into LWS notification envelopes (a {@code lws:Notification} JSON-LD
 * document wrapping an Activity Streams 2.0 {@code Create}/{@code Update}/{@code Delete} activity)
 * and dispatches them to every subscription that covers the resource and whose subscriber is
 * authorized to read it.
 *
 * @author Erich Bremer
 */
public final class NotificationEmitter implements ResourceEventListener {

    private static final Logger log = LoggerFactory.getLogger(NotificationEmitter.class);
    private static final String CONTENT_TYPE = "application/ld+json";

    private final SubscriptionService subscriptions;
    private final WebhookDispatcher dispatcher;
    private final ResourceService resources;
    private final LwsConfiguration config;

    public NotificationEmitter(SubscriptionService subscriptions, WebhookDispatcher dispatcher,
            ResourceService resources, LwsConfiguration config) {
        this.subscriptions = subscriptions;
        this.dispatcher = dispatcher;
        this.resources = resources;
        this.config = config;
    }

    @Override
    public void onResourceEvent(ResourceEvent event) {
        List<Subscription> matches = subscriptions.activeMatching(event.iri());
        if (matches.isEmpty()) {
            return;
        }
        byte[] body = null;
        for (Subscription subscription : matches) {
            LwsPrincipal subscriber = subscription.subscriberWebId() == null
                    ? null : new LwsPrincipal(subscription.subscriberWebId(), null, null);
            if (!authorizedToReceive(subscriber, event)) {
                log.debug("Suppressing notification of {} to {} (not authorized to read)",
                        event.iri(), subscription.id());
                continue;
            }
            if (body == null) {
                body = buildNotification(event);
            }
            dispatcher.deliver(subscription, body, CONTENT_TYPE);
        }
    }

    private boolean authorizedToReceive(LwsPrincipal subscriber, ResourceEvent event) {
        // The resource no longer exists for a delete, so fall back to its parent container.
        if (event.kind() == com.ebremer.lws.server.core.ActivityKind.DELETE) {
            String parent = parentIriOf(event.iri());
            return parent == null || resources.canRead(subscriber, parent);
        }
        return resources.canRead(subscriber, event.iri());
    }

    /**
     * Deliver an access-event notification (lws10-core access requests): a {@code Create} activity
     * about a newly created access request/grant, sent to the {@code inbox} the document carries.
     */
    public void notifyAccessCreated(String inbox, String objectIri, boolean grant, String actorWebId, Instant when) {
        byte[] body = buildEnvelope(objectIri, grant ? "lws:AccessGrant" : "lws:AccessRequest",
                "Create", actorWebId, when.toString());
        dispatcher.deliverTo(inbox, body, CONTENT_TYPE);
    }

    private byte[] buildNotification(ResourceEvent event) {
        String objectType = event.type() == ResourceType.CONTAINER ? "lws:Container" : "lws:DataResource";
        return buildEnvelope(event.iri(), objectType, capitalize(event.kind().name()),
                event.actorWebId(), event.when().toString());
    }

    /** Build a {@code lws:Notification} JSON-LD envelope wrapping a single AS2 activity. */
    private byte[] buildEnvelope(String objectIri, String objectType, String activityType,
            String actorWebId, String published) {
        JsonObject context = Json.createObjectBuilder()
                .add("lws", LWS.NS)
                .add("storage", Json.createObjectBuilder().add("@id", "lws:storage").add("@type", "@id"))
                .add("activity", "lws:activity")
                .add("Notification", "lws:Notification")
                .build();
        JsonArray contextArray = Json.createArrayBuilder()
                .add("https://www.w3.org/ns/activitystreams")
                .add(context)
                .build();

        JsonObject object = Json.createObjectBuilder()
                .add("id", objectIri)
                .add("type", objectType)
                .build();

        JsonObjectBuilder activity = Json.createObjectBuilder()
                .add("id", "urn:uuid:" + UUID.randomUUID())
                .add("type", activityType)
                .add("published", published)
                .add("object", object);
        if (actorWebId != null) {
            activity.add("actor", actorWebId);
        }

        JsonObject notification = Json.createObjectBuilder()
                .add("@context", contextArray)
                .add("type", "Notification")
                .add("storage", config.storageRootIri())
                .add("activity", Json.createArrayBuilder().add(activity).build())
                .build();
        return notification.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String parentIriOf(String iri) {
        String path = Iris.toPath(config.baseUri(), iri);
        if (path == null) {
            return null;
        }
        String parent = Iris.parentPath(path);
        return parent == null ? null : Iris.toIri(config.baseUri(), parent);
    }

    private static String capitalize(String s) {
        return s.charAt(0) + s.substring(1).toLowerCase();
    }
}
