package com.ebremer.lws.server.core;

import com.ebremer.lws.server.vocab.AS;
import org.apache.jena.rdf.model.Resource;

/**
 * The resource change kinds the LWS notifications spec requires servers to support, mapped to
 * their Activity Streams 2.0 activity types.
 *
 * <p>{@link #MOVE} is required only of a server that lets clients move resources between containers
 * (lws10-core, Activity Types), which this one does unless {@code lws.move.applies-to} turns it off.
 * One move is one {@code MOVE} event, about the resource whose {@code up} link changed; a moved
 * container's descendants raise none of their own.
 *
 * @author Erich Bremer
 */
public enum ActivityKind {

    CREATE(AS.Create),
    UPDATE(AS.Update),
    DELETE(AS.Delete),
    MOVE(AS.Move);

    private final Resource as2Type;

    ActivityKind(Resource as2Type) {
        this.as2Type = as2Type;
    }

    public Resource as2Type() {
        return as2Type;
    }
}
