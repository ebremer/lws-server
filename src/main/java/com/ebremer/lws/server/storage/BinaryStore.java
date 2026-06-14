package com.ebremer.lws.server.storage;

import java.io.IOException;
import java.io.InputStream;

/**
 * Storage for the bytes of non-RDF (data) resources. The metadata describing each blob
 * (content type, size, etag, containment, owner) lives in the {@code RdfStore}; only the
 * opaque bytes live here, keyed by a storage-relative key.
 *
 * @author Erich Bremer
 */
public interface BinaryStore {

    /** Result of storing a blob. */
    record StoredBlob(long size, String sha256Hex) {
    }

    boolean exists(String key);

    /** Open the blob for reading. Caller closes the stream. */
    InputStream read(String key) throws IOException;

    /** Store (replacing any existing blob) and return its size and SHA-256. The stream is fully consumed. */
    StoredBlob write(String key, InputStream data) throws IOException;

    void delete(String key) throws IOException;

    long size(String key) throws IOException;
}
