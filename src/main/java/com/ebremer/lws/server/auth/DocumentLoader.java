package com.ebremer.lws.server.auth;

/**
 * Fetches the text of a controlled-identifier (or DID) document by dereferencing its URL.
 * Pluggable so it can be stubbed in tests.
 *
 * @author Erich Bremer
 */
@FunctionalInterface
public interface DocumentLoader {

    /** Return the document body at {@code url}, or {@code null} if it cannot be retrieved. */
    String load(String url);
}
