package com.ebremer.lws.server.vocab;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

/**
 * A minimal subset of the Activity Streams 2.0 vocabulary, used to express
 * the {@code Create} / {@code Update} / {@code Delete} activities carried inside
 * LWS notification envelopes.
 *
 * <p>Namespace: {@code https://www.w3.org/ns/activitystreams#}.
 *
 * @author Erich Bremer
 */
public final class AS {

    private AS() {
    }

    public static final String NS = "https://www.w3.org/ns/activitystreams#";
    public static final String PREFIX = "as";

    public static String getURI() {
        return NS;
    }

    private static final Model M = ModelFactory.createDefaultModel();

    // Activity types required by the LWS notifications spec.
    public static final Resource Create = M.createResource(NS + "Create");
    public static final Resource Update = M.createResource(NS + "Update");
    public static final Resource Delete = M.createResource(NS + "Delete");

    // Properties.
    public static final Property actor = M.createProperty(NS + "actor");
    public static final Property object = M.createProperty(NS + "object");
    public static final Property target = M.createProperty(NS + "target");
    public static final Property origin = M.createProperty(NS + "origin");
    public static final Property published = M.createProperty(NS + "published");
}
