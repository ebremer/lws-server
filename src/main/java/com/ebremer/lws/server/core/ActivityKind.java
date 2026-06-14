package com.ebremer.lws.server.core;

import com.ebremer.lws.server.vocab.AS;
import org.apache.jena.rdf.model.Resource;

/**
 * The resource change kinds the LWS notifications spec requires servers to support, mapped to
 * their Activity Streams 2.0 activity types.
 *
 * @author Erich Bremer
 */
public enum ActivityKind {

    CREATE(AS.Create),
    UPDATE(AS.Update),
    DELETE(AS.Delete);

    private final Resource as2Type;

    ActivityKind(Resource as2Type) {
        this.as2Type = as2Type;
    }

    public Resource as2Type() {
        return as2Type;
    }
}
