package com.ebremer.lws.server.core;

import java.time.Instant;

/**
 * Immutable administrative metadata describing a single LWS resource. This is the record
 * the server keeps in its metadata (RDF) store; the resource's <em>content</em> lives either
 * as a named graph (RDF) or in the binary store (non-RDF).
 *
 * @param iri         the resource IRI (also the named-graph name for RDF resources)
 * @param type        the resource kind
 * @param parentIri   the parent container IRI, or {@code null} for the storage root
 * @param created     creation instant
 * @param modified    last-modified instant
 * @param etag        opaque entity-tag (unquoted)
 * @param contentType media type for non-RDF resources, otherwise {@code null}
 * @param size        byte size for non-RDF resources, otherwise -1
 * @param binaryKey   binary-store key for non-RDF resources, otherwise {@code null}
 * @param owner       owner WebID/controlled-identifier, or {@code null}
 * @param publicRead  whether the resource is world-readable
 * @param digest      hex SHA-256 of the content for non-RDF resources (RFC 9530 Repr-Digest), else {@code null}
 *
 * @author Erich Bremer
 */
public record LwsResource(
        String iri,
        ResourceType type,
        String parentIri,
        Instant created,
        Instant modified,
        String etag,
        String contentType,
        long size,
        String binaryKey,
        String owner,
        boolean publicRead,
        String digest) {

    public boolean isContainer() {
        return type == ResourceType.CONTAINER;
    }

    public boolean isRdf() {
        return type.isRdf();
    }

    /** The HTTP entity-tag value, quoted per RFC 9110. */
    public String quotedEtag() {
        return etag == null ? null : "\"" + etag + "\"";
    }

    public LwsResource withEtag(String newEtag) {
        return new LwsResource(iri, type, parentIri, created, modified, newEtag,
                contentType, size, binaryKey, owner, publicRead, digest);
    }

    public LwsResource withModified(Instant newModified) {
        return new LwsResource(iri, type, parentIri, created, newModified, etag,
                contentType, size, binaryKey, owner, publicRead, digest);
    }
}
