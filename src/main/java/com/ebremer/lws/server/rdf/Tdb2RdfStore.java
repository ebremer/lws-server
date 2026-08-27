package com.ebremer.lws.server.rdf;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;
import org.apache.jena.query.Dataset;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.query.ReadWrite;
import org.apache.jena.query.TxnType;
import org.apache.jena.rdfconnection.RDFConnection;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.DatasetGraphWrapper;
import org.apache.jena.tdb2.TDB2Factory;

/**
 * {@link RdfStore} backed by a local, transactional Apache Jena TDB2 dataset. This is the
 * default metadata store. Each unit of work runs in a real ACID transaction.
 *
 * @author Erich Bremer
 */
public final class Tdb2RdfStore implements RdfStore {

    private final Dataset dataset;

    public Tdb2RdfStore(Path location) {
        try {
            Files.createDirectories(location);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot create TDB2 directory: " + location, e);
        }
        this.dataset = TDB2Factory.connectDataset(location.toString());
    }

    public Tdb2RdfStore(Dataset dataset) {
        this.dataset = dataset;
    }

    /** The underlying dataset, e.g. to share with an embedded SPARQL (Fuseki) endpoint. */
    public Dataset dataset() {
        return dataset;
    }

    @Override
    public <T> T read(Function<RDFConnection, T> action) {
        return unitOfWork(TxnType.READ, action);
    }

    @Override
    public <T> T write(Function<RDFConnection, T> action) {
        return unitOfWork(TxnType.WRITE, action);
    }

    /**
     * Run one unit of work, opening a transaction only when this thread has none, and resolving it
     * only in the frame that opened it.
     *
     * <p><strong>Why this no longer uses {@code Txn.calculateRead}/{@code calculateWrite}.</strong>
     * Those join an already-open transaction rather than nest one, which is what makes an
     * authorization decision inside a write callback work at all — every {@code authorize(...)}
     * reaches {@code OwnerAuthorizer.allows} or {@code WacAclService.fetchAcl}, and each of those
     * calls {@link #read} again. But {@code Txn}'s exception path is
     * {@code onThrowable -> abort(); end();} with <em>no</em> check of whether that frame began the
     * transaction, and every {@code RDFConnection} operation — {@code querySelect}, {@code fetch},
     * {@code update}, {@code put} — is itself such a frame. So a throw anywhere inside a callback
     * tore down the caller's transaction (finding N3).
     *
     * <p><strong>Measured, on {@code DatasetFactory.createTxnMem()}, against the previous code:</strong>
     * a write callback that inserted a triple, then swallowed an exception raised inside a
     * {@code conn.querySelect} row handler — the swallow being this codebase's own house style, as
     * in {@code WacAclService.prepare} and {@code SearchIndexService.onResourceEvent} — left the
     * ambient transaction <em>closed</em>. The triple written before the throw was lost, and the
     * triple written after it committed on its own, outside any transaction and with the writer lock
     * released mid-callback. Not a narrow race: a partially applied, non-atomic write, which is
     * precisely the hazard {@link RdfStore}'s own contract says the TDB2 backend does not have.
     *
     * <p><strong>The fix.</strong> The outermost frame begins and resolves the transaction on the
     * real dataset itself; the callback is handed a connection over a view whose transaction control
     * is inert. Jena's inner frames still see {@code isInTransaction() == true} and so join, read
     * their own uncommitted writes, and skip commit — exactly as before — but their {@code abort()}
     * and {@code end()} can no longer reach the real transaction. The frame that began it is the
     * only one that can resolve it, which is the only frame that can resolve it correctly.
     */
    private <T> T unitOfWork(TxnType type, Function<RDFConnection, T> action) {
        boolean outermost = !dataset.isInTransaction();
        // The connection is built BEFORE the transaction opens, and the begin sits inside the try.
        // Anything thrown between those two points would otherwise orphan a write transaction on a
        // pooled request thread — and an orphan is permanent and silent: every later unit of work on
        // that thread sees isInTransaction() and assumes it is nested, so it commits nothing and
        // still returns normally, while the TDB2 writer lock is never released and every other
        // thread's write blocks forever. Measured against exactly one orphan.
        RDFConnection conn = RDFConnection.connect(DatasetFactory.wrap(new InertTxn(dataset.asDatasetGraph())));
        try {
            if (outermost) {
                dataset.begin(type);
            }
            T result = action.apply(conn);
            if (outermost) {
                if (!dataset.isInTransaction()) {
                    // Unreachable while InertTxn is in place, and kept because the day it becomes
                    // reachable the alternative is silently reporting a write that never happened.
                    throw new IllegalStateException("The " + type + " unit of work was ended from "
                            + "inside its own callback; nothing was committed");
                }
                dataset.commit();
            }
            return result;
        } catch (RuntimeException | Error e) {
            if (outermost && dataset.isInTransaction()) {
                try {
                    dataset.abort();
                } catch (RuntimeException | Error cleanup) {
                    e.addSuppressed(cleanup);
                }
            }
            throw e;
        } finally {
            conn.close();
            if (outermost && dataset.isInTransaction()) {
                dataset.end();
            }
        }
    }

    /**
     * A view of the dataset whose transaction <em>control</em> does nothing.
     *
     * <p>Everything else delegates, so data written through this view is written to the real
     * dataset inside the real transaction and is read back by it. Only {@code begin}/{@code commit}/
     * {@code abort}/{@code end} are inert, so that the nested {@code Txn} frames Jena opens for
     * every connection operation cannot resolve a transaction they did not begin.
     *
     * <p>{@code isInTransaction}, {@code transactionMode}, {@code transactionType} and
     * {@code promote} deliberately still delegate: those are questions <em>about</em> the ambient
     * transaction, and answering them from the real dataset is what keeps Jena's own compatibility
     * checks — a write joining a read-only snapshot, say — behaving exactly as they do today.
     *
     * <p>{@code close} is inert too. {@code RDFConnectionLocal.close()} only drops its own reference,
     * but nothing about that is contractual, and closing the shared dataset at the end of a request
     * would take the whole store down with it.
     */
    private static final class InertTxn extends DatasetGraphWrapper {

        InertTxn(DatasetGraph wrapped) {
            super(wrapped);
        }

        @Override
        public void begin() {
            // inert: see the class javadoc
        }

        @Override
        public void begin(TxnType type) {
            // inert
        }

        @Override
        public void begin(ReadWrite readWrite) {
            // inert
        }

        @Override
        public void commit() {
            // inert
        }

        @Override
        public void abort() {
            // inert
        }

        @Override
        public void end() {
            // inert
        }

        @Override
        public void close() {
            // inert: the wrapped dataset outlives every unit of work
        }
    }

    /**
     * Delegates to TDB2's own per-thread transaction state rather than tracking depth here. A
     * hand-rolled counter would have to be incremented and decremented around every unit of work,
     * and a single missed decrement on a pooled request thread would pin that worker into refusing
     * outbound fetches for the life of the process. This has no such failure mode: it is the same
     * state TDB2 consults to decide whether a nested call is already in a transaction.
     */
    @Override
    public boolean inUnitOfWork() {
        return dataset.isInTransaction();
    }

    @Override
    public void close() {
        dataset.close();
    }
}
