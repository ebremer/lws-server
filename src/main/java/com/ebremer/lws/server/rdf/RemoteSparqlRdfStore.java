package com.ebremer.lws.server.rdf;

import java.util.function.Function;
import org.apache.jena.rdfconnection.RDFConnection;
import org.apache.jena.rdfconnection.RDFConnectionRemote;
import org.apache.jena.rdfconnection.RDFConnectionRemoteBuilder;

/**
 * {@link RdfStore} backed by any remote SPARQL 1.1 service exposing Query, Update and the
 * Graph Store Protocol. This demonstrates that the metadata store is not tied to TDB2: point
 * it at Fuseki, GraphDB, Blazegraph, Neptune, etc.
 *
 * <p><b>Experimental, and refused unless {@code lws.sparql.remote.accept-no-transactions=true}
 * (finding M16).</b> Remote SPARQL has no cross-statement transaction concept: {@link #read} and
 * {@link #write} are the same method, and a callback that issues several requests is several
 * independent operations. {@code ResourceRegistry.put} alone is a {@code DELETE WHERE} followed by a
 * Graph Store {@code POST}; {@code ResourceService.create} and a recursive delete chain five or more.
 * Concretely, on this backend:
 * <ul>
 *   <li>the {@code If-Match} comparison inside a write is no longer a compare-and-swap, so two
 *       clients holding the same entity-tag can both succeed and the second silently discards the
 *       first (the lost update H23 exists to prevent);</li>
 *   <li>a deleted resource's ACL and linkset are erased by later requests that can fail on their own,
 *       so a path re-created afterwards can inherit the old ACL (H24);</li>
 *   <li>binary content and the metadata describing it are committed separately, so a failure between
 *       them leaves them describing different bytes (H13/H14);</li>
 *   <li>the linkset read-modify-write (M18) and the storage quota are advisory;</li>
 *   <li>a concurrent reader between the two halves of a registry {@code put} sees a spurious
 *       {@code 404}, and two concurrent POSTs with the same {@code Slug} pick the same name.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class RemoteSparqlRdfStore implements RdfStore {

    private final String queryEndpoint;
    private final String updateEndpoint;
    private final String gspEndpoint;

    public RemoteSparqlRdfStore(String queryEndpoint, String updateEndpoint, String gspEndpoint) {
        this.queryEndpoint = queryEndpoint;
        this.updateEndpoint = updateEndpoint;
        this.gspEndpoint = gspEndpoint;
    }

    private <T> T run(Function<RDFConnection, T> action) {
        RDFConnectionRemoteBuilder b = RDFConnectionRemote.newBuilder();
        if (queryEndpoint != null && !queryEndpoint.isBlank()) {
            b.queryEndpoint(queryEndpoint);
        }
        if (updateEndpoint != null && !updateEndpoint.isBlank()) {
            b.updateEndpoint(updateEndpoint);
        }
        if (gspEndpoint != null && !gspEndpoint.isBlank()) {
            b.gspEndpoint(gspEndpoint);
        }
        try (RDFConnection conn = b.build()) {
            return action.apply(conn);
        }
    }

    @Override
    public <T> T read(Function<RDFConnection, T> action) {
        return run(action);
    }

    @Override
    public <T> T write(Function<RDFConnection, T> action) {
        return run(action);
    }

    @Override
    public void close() {
        // nothing to close; connections are per-operation
    }
}
