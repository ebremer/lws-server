package com.ebremer.lws.server.rdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.apache.jena.query.Dataset;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.query.ReadWrite;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.TestDirs;

/**
 * {@link Tdb2RdfStore} is the default metadata store and the only backend {@link RdfStore}'s
 * contract says makes a unit of work atomic — yet nothing tested the class directly.
 * {@link NestedUnitOfWorkTest} pins the nested-transaction semantics of finding N3, but it does so
 * entirely over {@code DatasetFactory.createTxnMem()}: the on-disk constructor, {@link
 * Tdb2RdfStore#dataset()} and the two {@link RdfStore} defaults have no executed lines anywhere.
 *
 * <p>This class covers what is left, and covers the commit/abort pair on a <em>real TDB2 dataset</em>
 * rather than on the in-memory one. That distinction is the point: the atomicity every
 * compare-and-swap (H23), cascading ACL and linkset erasure (H24) and retired blob key (H13/H14) in
 * the service layer is built on is a claim about TDB2's journal, not about
 * {@code DatasetGraphInMemory}, and it is precisely the claim {@code RemoteSparqlRdfStore} cannot
 * honour. An in-memory rehearsal of it proves the wrapper, not the backend.
 *
 * <p>No {@code @TempDir} here, deliberately — this is the class that memory-maps its files. See
 * {@link TestDirs}.
 *
 * @author Erich Bremer
 */
class Tdb2RdfStoreTest {

    private static final String INSERT_COMMITTED =
            "INSERT DATA { GRAPH <urn:g> { <urn:s> <urn:p> \"committed\" } }";
    private static final String ASK_COMMITTED =
            "ASK { GRAPH <urn:g> { <urn:s> <urn:p> \"committed\" } }";
    private static final String INSERT_ABORTED =
            "INSERT DATA { GRAPH <urn:g> { <urn:s> <urn:p> \"aborted\" } }";
    private static final String ASK_ABORTED =
            "ASK { GRAPH <urn:g> { <urn:s> <urn:p> \"aborted\" } }";

    /**
     * A location two levels below a fresh temporary root, so neither the leaf nor its parent exists
     * when the constructor runs. That is the shape a first start really has: a deployment configures
     * {@code lws.data-dir} and the store opens {@code <data-dir>/tdb2} underneath it.
     */
    private static final Path DISK_LOCATION = TestDirs.create().resolve("nested/tdb2");

    private static Tdb2RdfStore disk;

    @BeforeAll
    static void openTheOnDiskStore() {
        disk = new Tdb2RdfStore(DISK_LOCATION);
    }

    /**
     * Closed, but the directory is deliberately not deleted here: Windows will not unmap TDB2's
     * files while this JVM lives, so {@link TestDirs} sweeps it on the next run instead.
     */
    @AfterAll
    static void closeTheOnDiskStore() {
        disk.close();
    }

    /**
     * {@code Files.createDirectories}, not {@code createDirectory}: a missing parent must not be an
     * error on a first start. The second assertion is what separates "the test made a directory"
     * from "TDB2 opened it" — an empty directory would mean the connect step never happened.
     */
    @Test
    void theOnDiskConstructorCreatesTheWholeDirectoryTreeAndOpensItAsATdb2Dataset() throws Exception {
        assertTrue(Files.isDirectory(DISK_LOCATION),
                "the constructor must create its location, parents included");
        try (Stream<Path> entries = Files.list(DISK_LOCATION)) {
            assertTrue(entries.findAny().isPresent(),
                    "TDB2 must have laid its storage out in the directory the constructor created");
        }
    }

    /** The commit half of the ACID claim, on the backend the claim is about. */
    @Test
    void aWriteCommitsAndALaterSeparateReadSeesIt() {
        disk.writeDo(conn -> conn.update(INSERT_COMMITTED));

        assertTrue(holds(disk, ASK_COMMITTED),
                "a committed write must be visible to a later, independent read transaction");
    }

    /**
     * The abort half, through the {@code write} (value-returning) form, which no other test drives
     * to failure. The rollback must be TDB2's own — the callback wrote real quads before it threw,
     * so anything less than a genuine abort leaves them in the dataset.
     */
    @Test
    void aWriteThatThrowsLeavesNothingBehind() {
        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> disk.write(conn -> {
                    conn.update(INSERT_ABORTED);
                    throw new IllegalStateException("boom");
                }));

        assertEquals("boom", thrown.getMessage(),
                "the caller's failure must reach the caller unchanged, not be wrapped by the store");
        assertFalse(holds(disk, ASK_ABORTED),
                "an aborted TDB2 write must leave nothing behind");
        assertFalse(disk.inUnitOfWork(),
                "the transaction must be ended as well as aborted, or this thread holds the writer lock");
    }

    /**
     * The embedded SPARQL endpoint is handed {@code store.dataset().asDatasetGraph()}, which is how
     * it shares this store's transactions instead of opening a second, independent transactional
     * view of the same files. A {@code dataset()} that copied or re-wrapped would break that
     * silently — the endpoint would still answer queries, just from its own world.
     */
    @Test
    void datasetReturnsTheVeryInstanceItWasGiven() {
        Dataset given = DatasetFactory.createTxnMem();
        Tdb2RdfStore store = new Tdb2RdfStore(given);
        try {
            assertSame(given, store.dataset(),
                    "dataset() must hand back the instance the constructor was given");
        } finally {
            store.close();
        }
    }

    /**
     * The two {@link RdfStore} defaults are the form most callers use, and each has a way to be
     * wrong that nothing else would notice: a {@code readDo} that delegated to {@code write} would
     * take TDB2's single writer lock for every read in the server, and a {@code writeDo} whose
     * callback returns nothing would look identical whether or not it committed. So this asserts the
     * kind of transaction each one opened, and that the write landed.
     */
    @Test
    void readDoAndWriteDoOpenTheRightKindOfUnitOfWork() {
        Tdb2RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        try {
            List<ReadWrite> modes = new ArrayList<>();
            store.writeDo(conn -> {
                modes.add(store.dataset().transactionMode());
                conn.update(INSERT_COMMITTED);
            });
            store.readDo(conn -> modes.add(store.dataset().transactionMode()));

            assertEquals(List.of(ReadWrite.WRITE, ReadWrite.READ), modes,
                    "writeDo must open a WRITE unit of work and readDo a READ one");
            assertTrue(holds(store, ASK_COMMITTED),
                    "writeDo must commit, even though its callback returns nothing to commit for it");
        } finally {
            store.close();
        }
    }

    /**
     * A {@code boolean}-returning wrapper, not an inlined {@code store.read(...)}: with the result
     * inferred from {@code assertTrue}'s parameter, javac binds it to the {@code BooleanSupplier}
     * overload instead of the {@code boolean} one and the call does not compile.
     */
    private static boolean holds(Tdb2RdfStore store, String ask) {
        return store.read(conn -> conn.queryAsk(ask));
    }
}
