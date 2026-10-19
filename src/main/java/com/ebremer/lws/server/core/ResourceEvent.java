package com.ebremer.lws.server.core;

import java.time.Instant;
import java.util.Set;

/**
 * A resource change emitted by the service layer, consumed by the notification subsystem.
 *
 * @param kind        the change kind
 * @param iri         the affected resource IRI; for a {@code MOVE}, the IRI it has <em>after</em> the move
 * @param type        the resource kind at the time of the event
 * @param actorWebId  the agent that caused the change, or {@code null} if anonymous/system
 * @param when        the event instant
 * @param audience    for a DELETE, the ids of subscriptions that may be told, captured before the
 *                    resource was removed (see {@link DeleteAudience}); for a MOVE, the ids of
 *                    subscriptions that could read the resource at its previous IRI, captured
 *                    before the move for the same reason; {@code null} for every other kind, where
 *                    the resource still exists and can be authorized against directly
 * @param previousIri for a MOVE, the IRI the resource had before it; otherwise {@code null}
 * @param origin      for a MOVE, the container the resource was removed from; otherwise {@code null}
 * @param target      for a MOVE, the container the resource was added to; otherwise {@code null}
 *
 * @author Erich Bremer
 */
public record ResourceEvent(ActivityKind kind, String iri, ResourceType type, String actorWebId,
        Instant when, Set<String> audience, String previousIri, String origin, String target) {

    /** An event with no captured audience: every kind but {@code DELETE} and {@code MOVE}. */
    public ResourceEvent(ActivityKind kind, String iri, ResourceType type, String actorWebId, Instant when) {
        this(kind, iri, type, actorWebId, when, null);
    }

    /** An event with a captured audience and no relocation: a {@code DELETE}. */
    public ResourceEvent(ActivityKind kind, String iri, ResourceType type, String actorWebId, Instant when,
            Set<String> audience) {
        this(kind, iri, type, actorWebId, when, audience, null, null, null);
    }

    /**
     * A {@code MOVE}: the resource now at {@code iri} was at {@code previousIri}, a member of
     * {@code origin}, and is now a member of {@code target}.
     */
    public static ResourceEvent moved(String iri, String previousIri, ResourceType type, String actorWebId,
            Instant when, Set<String> audience, String origin, String target) {
        return new ResourceEvent(ActivityKind.MOVE, iri, type, actorWebId, when, audience, previousIri,
                origin, target);
    }
}
