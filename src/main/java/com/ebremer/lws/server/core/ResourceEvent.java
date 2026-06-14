package com.ebremer.lws.server.core;

import java.time.Instant;

/**
 * A resource change emitted by the service layer, consumed by the notification subsystem.
 *
 * @param kind        the change kind
 * @param iri         the affected resource IRI
 * @param type        the resource kind at the time of the event
 * @param actorWebId  the agent that caused the change, or {@code null} if anonymous/system
 * @param when        the event instant
 *
 * @author Erich Bremer
 */
public record ResourceEvent(ActivityKind kind, String iri, ResourceType type, String actorWebId, Instant when) {
}
