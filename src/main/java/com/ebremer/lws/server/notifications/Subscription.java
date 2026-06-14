package com.ebremer.lws.server.notifications;

import java.time.Instant;
import java.util.List;

/**
 * A webhook notification subscription.
 *
 * @param id               the subscription resource IRI
 * @param subscriberWebId  the owner (subscriber) WebID, or {@code null} if created anonymously
 * @param topics           the resource IRIs covered (a container topic is recursive)
 * @param inbox            the destination URL notifications are POSTed to
 * @param expires          optional expiry instant
 * @param active           whether the subscription is currently active
 * @param failureCount     consecutive delivery failures
 * @param created          creation instant
 *
 * @author Erich Bremer
 */
public record Subscription(
        String id,
        String subscriberWebId,
        List<String> topics,
        String inbox,
        Instant expires,
        boolean active,
        int failureCount,
        Instant created) {

    public boolean isExpired(Instant now) {
        return expires != null && expires.isBefore(now);
    }

    /** True if this subscription's topics cover {@code resourceIri} (directly or via a container). */
    public boolean covers(String resourceIri) {
        for (String topic : topics) {
            if (topic.equals(resourceIri)) {
                return true;
            }
            if (topic.endsWith("/") && resourceIri.startsWith(topic) && !resourceIri.equals(topic)) {
                return true;
            }
        }
        return false;
    }
}
