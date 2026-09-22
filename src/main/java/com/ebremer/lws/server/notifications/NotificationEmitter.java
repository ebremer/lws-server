package com.ebremer.lws.server.notifications;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.ActivityKind;
import com.ebremer.lws.server.core.Iris;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.RequestContext;
import com.ebremer.lws.server.core.ResourceEvent;
import com.ebremer.lws.server.core.ResourceEventListener;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.core.ResourceType;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Turns {@link ResourceEvent}s into LWS notifications and dispatches them to every subscription that
 * covers the resource and whose subscriber is authorized to read it.
 *
 * <p>A notification is the lws10-core Notification Data Model: an {@code application/lws+json}
 * envelope of type {@code Notification} carrying the {@code storage} it concerns and one Activity
 * Streams 2.0 {@code activity} — {@code Create}, {@code Update} or {@code Delete} — whose
 * {@code type} and whose {@code object}'s {@code type} are arrays, whose {@code published} is an
 * RFC 3339 timestamp, and which names the container the resource was added to ({@code target}, on a
 * {@code Create}) or removed from ({@code origin}, on a {@code Delete}). The {@code actor} is
 * omitted unless {@code lws.notifications.include-actor} is set, as the core's privacy
 * considerations advise.
 *
 * @author Erich Bremer
 */
public final class NotificationEmitter implements ResourceEventListener {

    private static final Logger log = LoggerFactory.getLogger(NotificationEmitter.class);
    /** Notification deliveries are {@code application/lws+json} (lws10-notifications-webhook). */
    private static final String CONTENT_TYPE = "application/lws+json";
    /** The envelope's context: the LWS context first, then Activity Streams (lws10-core). */
    private static final String ACTIVITY_STREAMS_CONTEXT = "https://www.w3.org/ns/activitystreams";

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
            if (!authorizedToReceive(subscription, event)) {
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

    /**
     * The ids of subscriptions covering {@code iri} whose subscriber may read it <em>now</em>.
     *
     * <p>Called by {@code ResourceService} before a delete transaction opens, because afterwards the
     * resource's own ACL is gone and the question can no longer be answered honestly. See
     * {@link com.ebremer.lws.server.core.DeleteAudience}.
     */
    public Set<String> subscribersAllowedToKnow(String iri) {
        return asSubscriber(() -> {
            Set<String> allowed = new LinkedHashSet<>();
            for (Subscription subscription : subscriptions.activeMatching(iri)) {
                if (resources.canRead(subscriberOf(subscription), iri)) {
                    allowed.add(subscription.id());
                }
            }
            return allowed;
        });
    }

    private boolean authorizedToReceive(Subscription subscription, ResourceEvent event) {
        if (event.kind() == ActivityKind.DELETE) {
            // Decided before the resource was removed and carried here on the event. There is
            // nothing left to evaluate now: the resource is gone and its ACL with it, so asking
            // again would resolve through container inheritance and tell every reader of the parent
            // that a private child existed, its IRI, who deleted it and when (finding H19). No
            // captured audience means nobody — the direction the old parent fallback got backwards,
            // where a null parent path meant "deliver to everyone".
            return event.audience() != null && event.audience().contains(subscription.id());
        }
        return asSubscriber(() -> resources.canRead(subscriberOf(subscription), event.iri()));
    }

    private static LwsPrincipal subscriberOf(Subscription subscription) {
        return subscription.subscriberWebId() == null
                ? null : new LwsPrincipal(subscription.subscriberWebId(), null, null);
    }

    /**
     * Evaluate a subscriber's access with no request context at all.
     *
     * <p>Listeners run synchronously on the <em>writer's</em> thread, and {@link RequestContext} is a
     * thread-local holding the writer's {@code Origin} and {@code LWS-Purpose}. So a subscriber's
     * read decision was partly made from the headers of whoever happened to trigger the change:
     * a write from an allow-listed app delivered notifications to subscribers an
     * {@code acl:origin} rule was written to exclude, and the same write from anywhere else
     * withheld them (finding M31). Neither answer had anything to do with the subscriber.
     *
     * <p>Cleared rather than substituted, because a webhook delivery genuinely has no origin and
     * declares no purpose: an origin-restricted authorization should not apply to it, and
     * {@code originAllowed} refuses when no {@code Origin} is present — the fail-closed direction.
     * The writer's context is restored afterwards; it still belongs to the request in progress.
     */
    private <T> T asSubscriber(Supplier<T> decision) {
        String origin = RequestContext.origin();
        Set<String> purposes = RequestContext.purposes();
        RequestContext.clear();
        try {
            return decision.get();
        } finally {
            RequestContext.setOrigin(origin);
            RequestContext.setPurposes(purposes);
        }
    }

    /**
     * Deliver an access-event notification (lws10-core, Access Requests and Grants): a
     * {@code Create} activity about a newly created access request or grant, whose {@code target}
     * is the endpoint it was created in, sent to an inbox the document or the configuration names.
     */
    public void notifyAccessCreated(String inbox, String objectIri, boolean grant, String actorWebId, Instant when) {
        String endpoint = grant ? config.accessGrantsEndpointIri() : config.accessRequestsEndpointIri();
        byte[] body = buildEnvelope(objectIri, List.of("DataResource", grant ? "AccessGrant" : "AccessRequest"),
                "Create", endpoint, null, actorWebId, when);
        dispatcher.deliverTo(inbox, body, CONTENT_TYPE);
    }

    private byte[] buildNotification(ResourceEvent event) {
        String objectType = event.type() == ResourceType.CONTAINER ? "Container" : "DataResource";
        String parent = parentOf(event.iri());
        return buildEnvelope(event.iri(), List.of(objectType), capitalize(event.kind().name()),
                event.kind() == ActivityKind.CREATE ? parent : null,
                event.kind() == ActivityKind.DELETE ? parent : null,
                event.actorWebId(), event.when());
    }

    /** The container a resource belongs to, or {@code null} for the root and foreign IRIs. */
    private String parentOf(String iri) {
        String path = Iris.toPath(config.baseUri(), iri);
        String parent = path == null ? null : Iris.parentPath(path);
        return parent == null ? null : Iris.toIri(config.baseUri(), parent);
    }

    /**
     * Build a notification envelope wrapping a single activity.
     *
     * @param target the container the resource was added to (a {@code Create}), or {@code null}
     * @param origin the container the resource was removed from (a {@code Delete}), or {@code null}
     */
    private byte[] buildEnvelope(String objectIri, List<String> objectTypes, String activityType,
            String target, String origin, String actorWebId, Instant when) {
        JsonArrayBuilder types = Json.createArrayBuilder();
        objectTypes.forEach(types::add);
        JsonObject object = Json.createObjectBuilder()
                .add("id", objectIri)
                .add("type", types)
                .build();

        JsonObjectBuilder activity = Json.createObjectBuilder()
                .add("id", "urn:uuid:" + UUID.randomUUID())
                .add("type", Json.createArrayBuilder().add(activityType))
                .add("object", object);
        if (target != null) {
            activity.add("target", target);
        }
        if (origin != null) {
            activity.add("origin", origin);
        }
        // Who made the change is withheld by default: lws10-core says the actor SHOULD be omitted
        // and MAY be made configurable, because it tells every subscriber who edits what.
        if (actorWebId != null && config.notificationsIncludeActor()) {
            activity.add("actor", actorWebId);
        }
        activity.add("published", when.truncatedTo(ChronoUnit.MILLIS).toString());

        JsonObject notification = Json.createObjectBuilder()
                .add("@context", Json.createArrayBuilder().add(LWS.JSON_CONTEXT).add(ACTIVITY_STREAMS_CONTEXT))
                .add("type", "Notification")
                .add("storage", config.storageIri())
                .add("activity", activity)
                .build();
        return notification.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String capitalize(String s) {
        return s.charAt(0) + s.substring(1).toLowerCase();
    }
}
