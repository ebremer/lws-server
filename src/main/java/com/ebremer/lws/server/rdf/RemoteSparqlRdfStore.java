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
 * <p>Remote SPARQL has no cross-statement transaction concept, so each operation is
 * autocommitted; {@link #read} and {@link #write} differ only intent, not isolation.
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
