package com.ebremer.lws.server.core;

/**
 * The kinds of LWS resource this server manages.
 *
 * @author Erich Bremer
 */
public enum ResourceType {

    /** A container ({@code lws:Container}); the storage root is a container with no parent. */
    CONTAINER,
    /** An RDF data resource ({@code lws:DataResource}) whose content is stored as a named graph. */
    RDF_SOURCE,
    /** A non-RDF data resource ({@code lws:DataResource}) whose bytes are stored in the binary store. */
    NON_RDF_SOURCE;

    public boolean isContainer() {
        return this == CONTAINER;
    }

    public boolean isRdf() {
        return this == CONTAINER || this == RDF_SOURCE;
    }
}
