package com.ebremer.lws.server.rdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Finding N3 — a failure inside a unit of work must not resolve a transaction it did not open.
 *
 * <p>Jena's {@code Txn} helpers join an already-open transaction rather than nesting one, which is
 * what lets an authorization decision run inside a write callback at all: every {@code authorize}
 * reaches {@code OwnerAuthorizer.allows} or {@code WacAclService.fetchAcl}, and each of those opens
 * another unit of work. But {@code Txn}'s exception path is {@code abort(); end();} with no check of
 * whether that frame began the transaction — and every {@code RDFConnection} operation is itself
 * such a frame. So a throw anywhere inside a callback tore the caller's transaction down.
 *
 * <p>Measured against the pre-fix code, {@link #aSwallowedFailureInsideAQueryDoesNotEndTheTransaction}
 * showed the worst of it: the ambient transaction was gone, the triple written before the throw was
 * lost, and the triple written after it committed on its own, outside any transaction and with the
 * writer lock released mid-callback. Not a narrow race — a partially applied, non-atomic write.
 *
 * @author Erich Bremer
 */
class NestedUnitOfWorkTest {

    private static final String INSERT_A = "INSERT DATA { GRAPH <urn:g> { <urn:s> <urn:p> \"A\" } }";
    private static final String INSERT_B = "INSERT DATA { GRAPH <urn:g> { <urn:s> <urn:p> \"B\" } }";
    private static final String ASK_A = "ASK { GRAPH <urn:g> { <urn:s> <urn:p> \"A\" } }";
    private static final String ASK_B = "ASK { GRAPH <urn:g> { <urn:s> <urn:p> \"B\" } }";
    private static final String SELECT_ALL = "SELECT ?x WHERE { GRAPH <urn:g> { <urn:s> <urn:p> ?x } }";

    private Tdb2RdfStore store;

    @BeforeEach
    void setUp() {
        store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
    }

    /**
     * The regression. The swallow is this codebase's own house style — {@code WacAclService.prepare}
     * and {@code SearchIndexService.onResourceEvent} both catch and log rather than fail a request
     * over an advisory step — so the hazard is one ordinary refactor away wherever it is not fixed.
     */
    @Test
    void aSwallowedFailureInsideAQueryDoesNotEndTheTransaction() {
        AtomicBoolean stillOpen = new AtomicBoolean();
        store.writeDo(conn -> {
            conn.update(INSERT_A);
            try {
                conn.querySelect(SELECT_ALL, row -> {
                    throw new IllegalStateException("probe");
                });
            } catch (IllegalStateException expected) {
                // swallowed on purpose: the point is what the swallow leaves behind
            }
            stillOpen.set(store.inUnitOfWork());
            conn.update(INSERT_B);
        });

        assertTrue(stillOpen.get(),
                "the write transaction must survive a failure raised inside one of its own queries");
        assertTrue(committed(ASK_A), "the write made before the failure must still be committed");
        assertTrue(committed(ASK_B), "the write made after the failure must be committed");
    }

    /** The same shape one level up: a nested {@code read} that fails and is swallowed. */
    @Test
    void aSwallowedFailureInsideANestedReadDoesNotEndTheOuterWrite() {
        AtomicBoolean stillOpen = new AtomicBoolean();
        store.writeDo(conn -> {
            conn.update(INSERT_A);
            try {
                store.read(inner -> {
                    throw new IllegalStateException("probe");
                });
            } catch (IllegalStateException expected) {
                // as above
            }
            stillOpen.set(store.inUnitOfWork());
        });

        assertTrue(stillOpen.get(), "a nested read that fails must not resolve the outer transaction");
        assertTrue(committed(ASK_A), "the outer write must still commit");
    }

    /**
     * The other half, and the one that must not regress: a failure the callback does <em>not</em>
     * swallow still aborts everything. This is the guarantee {@code DeleteAtomicityTest} depends on.
     */
    @Test
    void aFailureThatPropagatesStillAbortsTheWholeUnitOfWork() {
        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> store.writeDo(conn -> {
                    conn.update(INSERT_A);
                    throw new IllegalStateException("boom");
                }));

        assertEquals("boom", thrown.getMessage());
        assertEquals(0, thrown.getSuppressed().length,
                "aborting a transaction this frame did open must not attach a suppressed failure");
        assertFalse(committed(ASK_A), "an aborted write must leave nothing behind");
        assertFalse(store.inUnitOfWork(), "the transaction must be ended, not merely aborted");
    }

    /** A nested read joins the ambient transaction, so it sees writes that are not yet committed. */
    @Test
    void aNestedReadSeesTheOuterTransactionUncommittedWrites() {
        boolean seen = store.write(conn -> {
            conn.update(INSERT_A);
            return store.read(inner -> inner.queryAsk(ASK_A));
        });
        assertTrue(seen, "a nested read must join the open transaction rather than snapshot around it");
        assertTrue(committed(ASK_A));
    }

    /** Graph-level operations still reach the real dataset through the transaction-inert view. */
    @Test
    void graphWritesAndReadsGoThroughToTheRealDataset() {
        store.writeDo(conn -> {
            Model m = ModelFactory.createDefaultModel();
            m.createResource("urn:s").addProperty(m.createProperty("urn:p"), "V");
            conn.put("urn:g2", m);
        });
        assertEquals(1, (long) store.read(conn -> conn.fetch("urn:g2").size()));
    }

    /** {@code inUnitOfWork} is per-thread, which is what H16's refusal-to-fetch rule rests on. */
    @Test
    void inUnitOfWorkIsPerThreadAndFalseOutsideAUnitOfWork() throws Exception {
        assertFalse(store.inUnitOfWork());
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch checked = new CountDownLatch(1);
        AtomicBoolean otherThreadSawATransaction = new AtomicBoolean(true);

        Thread observer = new Thread(() -> {
            try {
                inside.await(10, TimeUnit.SECONDS);
                otherThreadSawATransaction.set(store.inUnitOfWork());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                checked.countDown();
            }
        }, "observer");
        observer.start();

        store.writeDo(conn -> {
            assertTrue(store.inUnitOfWork(), "inside a write, this thread is in a unit of work");
            inside.countDown();
            try {
                checked.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        observer.join(10_000);

        assertFalse(otherThreadSawATransaction.get(), "another thread must not see this transaction");
        assertFalse(store.inUnitOfWork(), "the transaction must be ended once the write returns");
    }

    private boolean committed(String ask) {
        return store.read(conn -> conn.queryAsk(ask));
    }
}
