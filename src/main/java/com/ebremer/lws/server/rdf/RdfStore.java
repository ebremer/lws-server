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
 * store wraps each {@link #read}/{@link #write} in the appropriate transaction.
 *
 * <p><b>Only {@code Tdb2RdfStore} makes a unit of work atomic.</b> This interface used to say that
 * remote SPARQL backends "autocommit each operation", which reads like a weaker isolation level and
 * is really the absence of one: a callback that issues five requests is five independent operations
 * that another client can interleave with and that no failure rolls back. Every guarantee the service
 * layer builds on a {@link #write} callback — the {@code If-Match} compare-and-swap inside the write
 * that guards it (H23), ACL and linkset erasure committing with the delete (H24), blob keys retired
 * only once the metadata naming them commits (H13/H14) — holds on TDB2 and does not hold on
 * {@code RemoteSparqlRdfStore}. That is why {@code lws.sparql.mode=REMOTE} now refuses to start
 * without {@code lws.sparql.remote.accept-no-transactions=true} (finding M16): the difference is not
 * something an implementation note can carry.
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

    /**
     * True if the calling thread is already inside a unit of work on this store.
     *
     * <p>Backends that serialize writers use this to keep slow work — above all outbound HTTP —
     * off the critical section: TDB2 admits exactly one writer for the whole dataset, so anything
     * that blocks inside a {@link #write} callback blocks every other write in the storage. Code
     * that may have to dereference a remote document therefore asks this first and refuses rather
     * than fetching (see {@code WacAclService.groupMembers}); the work is done ahead of time
     * instead, through {@code Authorizer.prepare}.
     *
     * <p>The default is {@code false}, which is the correct answer for a backend that holds no
     * transaction at all.
     */
    default boolean inUnitOfWork() {
        return false;
    }

    @Override
    void close();
}
