package com.ebremer.lws.server.core;

import java.time.Instant;
import java.util.Set;

/**
 * A resource change emitted by the service layer, consumed by the notification subsystem.
 *
 * @param kind        the change kind
 * @param iri         the affected resource IRI
 * @param type        the resource kind at the time of the event
 * @param actorWebId  the agent that caused the change, or {@code null} if anonymous/system
 * @param when        the event instant
 * @param audience    for a DELETE, the ids of subscriptions that may be told, captured before the
 *                    resource was removed (see {@link DeleteAudience}); {@code null} for every other
 *                    kind, where the resource still exists and can be authorized against directly
 *
 * @author Erich Bremer
 */
public record ResourceEvent(ActivityKind kind, String iri, ResourceType type, String actorWebId,
        Instant when, Set<String> audience) {

    /** An event with no captured audience: every kind but {@code DELETE}. */
    public ResourceEvent(ActivityKind kind, String iri, ResourceType type, String actorWebId, Instant when) {
        this(kind, iri, type, actorWebId, when, null);
    }
}
