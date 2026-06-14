package com.ebremer.lws.server.rdf;

import java.util.function.Consumer;
import java.util.function.Function;
import org.apache.jena.rdfconnection.RDFConnection;

/**
 * The metadata store abstraction. All RDF access in the server goes through an
 * {@link RDFConnection}, which Jena implements identically over a local TDB2 dataset and over
 * any remote SPARQL 1.1 service (Query + Update + Graph Store Protocol). Swapping the backend
 * is therefore a single wiring change with no impact on the service layer.
 *
 * <p>Callers must <strong>not</strong> manage transactions on the supplied connection; the
 * store wraps each {@link #read}/{@link #write} in the appropriate transaction (for backends
 * that support transactions). For remote SPARQL backends each operation is autocommitted.
 *
 * @author Erich Bremer
 */
public interface RdfStore extends AutoCloseable {

    /** Run a read-only unit of work and return its result. */
    <T> T read(Function<RDFConnection, T> action);

    /** Run a read-write unit of work and return its result. */
    <T> T write(Function<RDFConnection, T> action);

    /** Run a read-only unit of work with no result. */
    default void readDo(Consumer<RDFConnection> action) {
        read(conn -> {
            action.accept(conn);
            return null;
        });
    }

    /** Run a read-write unit of work with no result. */
    default void writeDo(Consumer<RDFConnection> action) {
        write(conn -> {
            action.accept(conn);
            return null;
        });
    }

    @Override
    void close();
}
