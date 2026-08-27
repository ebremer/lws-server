package com.ebremer.lws.server.auth;

import org.apache.jena.rdf.model.Model;

/**
 * Fetches the text of a controlled-identifier (or DID) document by dereferencing its URL.
 * Pluggable so it can be stubbed in tests.
 *
 * <p>Implementations are the server's <strong>only</strong> sanctioned egress for
 * externally-supplied URLs during authentication and WAC group resolution: they apply the
 * {@link OutboundFetchPolicy} to every hop, bound the response size, and time-bound the request.
 * Callers must not fall back to {@code RDFDataMgr.loadModel(url)} or a bare {@code HttpClient},
 * both of which follow redirects without re-applying the policy.
 *
 * @author Erich Bremer
 */
@FunctionalInterface
public interface DocumentLoader {

    /** Return the document body at {@code url}, or {@code null} if it cannot be retrieved. */
    String load(String url);

    /**
     * Fetch and parse an RDF document at {@code url}, or return {@code null} if it cannot be
     * retrieved or parsed. The default implementation retrieves nothing, so a lambda-shaped
     * stub is never mistaken for a working RDF loader.
     */
    default Model loadRdf(String url) {
        return null;
    }
}
