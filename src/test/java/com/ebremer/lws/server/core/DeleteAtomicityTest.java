package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import org.apache.jena.query.DatasetFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.rdf.RdfStore;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;

/**
 * A resource and the state that belongs to it are deleted together or not at all (finding H24).
 *
 * <p>A deleted resource's ACL and linkset used to be erased by post-commit event listeners, each in
 * a transaction of its own and each swallowing whatever went wrong. So a cleanup that failed left
 * the ACL behind and only logged a warning — and a resource later created at the same path inherited
 * it, because an own-ACL outranks container inheritance. Whoever the old ACL named silently kept
 * read and write on a resource they had never been granted. These tests pin the two halves of the
 * fix: cleanup runs inside the delete's transaction, and a cleanup that fails takes the delete down
 * with it instead of being logged.
 *
 * @author Erich Bremer
 */
class DeleteAtomicityTest {

    private static final String BASE = "http://example.org";
    private static final LwsPrincipal ALICE = new LwsPrincipal("https://alice.example/#me", null, null);

    private RdfStore store;
    private ResourceService service;

    @BeforeEach
    void setUp(@TempDir Path dir) throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        // An owner, because this class asserts nothing about authorization and the
        // development posture now has to be asked for explicitly.
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        p.setProperty("lws.data-dir", dir.toString());
        LwsConfiguration config = LwsConfiguration.of(p);
        store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        service = new ResourceService(store, new FileSystemBinaryStore(config.blobDir()),
                new ResourceRegistry(), (principal, iri, mode) -> true, config, Clock.systemUTC());
        service.ensureStorageRoot();
    }

    @Test
    void cleanupRunsOnTheDeleteOwnConnectionInsideItsTransaction() {
        List<String> cleaned = new ArrayList<>();
        service.addDeleteCleanup((conn, iri) -> {
            assertTrue(store.inUnitOfWork(),
                    "a cleanup must run inside the delete transaction, not after it");
            cleaned.add(iri);
        });

        service.put("/note", ALICE, rdf("<#it> <http://schema.org/name> \"v1\" ."));
        service.delete("/note", ALICE);

        assertEquals(List.of(BASE + "/note"), cleaned);
    }

    @Test
    void everyMemberOfARecursiveDeleteIsCleanedUp() {
        List<String> cleaned = new ArrayList<>();
        service.addDeleteCleanup((conn, iri) -> cleaned.add(iri));

        service.put("/tree/", ALICE, container());
        service.put("/tree/inner/", ALICE, container());
        service.put("/tree/inner/leaf", ALICE, rdf("<#it> <http://schema.org/name> \"leaf\" ."));

        service.delete("/tree/", ALICE, true);

        // Descendants first, container last — the order the subtree walk produces. A recursive
        // delete that cleaned up only its top IRI would leave a stale ACL on every descendant,
        // which is the same privilege-inheritance hazard one level down.
        assertEquals(List.of(BASE + "/tree/inner/leaf", BASE + "/tree/inner/", BASE + "/tree/"), cleaned);
    }

    @Test
    void aFailingCleanupAbortsTheWholeDelete() {
        service.addDeleteCleanup((conn, iri) -> {
            throw new IllegalStateException("cleanup failed");
        });
        service.put("/keep", ALICE, rdf("<#it> <http://schema.org/name> \"v1\" ."));

        assertThrows(IllegalStateException.class, () -> service.delete("/keep", ALICE));

        assertTrue(service.stat("/keep").isPresent(),
                "the delete must not commit when the state belonging to the resource could not go with it");
        assertTrue(service.read("/keep", ALICE).isRdf(), "the content must survive the aborted delete too");
    }

    /** The bytes of a binary resource are unlinked only once the delete commits (H13 meets H24). */
    @Test
    void anAbortedDeleteLeavesBinaryContentReadable() throws Exception {
        service.addDeleteCleanup((conn, iri) -> {
            throw new IllegalStateException("cleanup failed");
        });
        service.put("/blob", ALICE, new ResourceService.WriteRequest("application/octet-stream",
                "payload".getBytes(StandardCharsets.UTF_8), ResourceService.TypeHint.NON_RDF_SOURCE, null));

        assertThrows(IllegalStateException.class, () -> service.delete("/blob", ALICE));

        LwsResource meta = service.stat("/blob").orElseThrow();
        try (InputStream in = service.openBinary(meta)) {
            assertEquals("payload", new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    /**
     * The post-commit fan-out keeps its old contract. A listener drives effects outside the store —
     * a notification, a search index — where a failure is logged and the delete still stands. Only
     * state that lives in the store moved into the transaction.
     */
    @Test
    void aFailingEventListenerStillDoesNotAbortTheDelete() {
        service.addEventListener(event -> {
            throw new IllegalStateException("listener failed");
        });
        service.put("/gone", ALICE, rdf("<#it> <http://schema.org/name> \"v1\" ."));

        service.delete("/gone", ALICE);

        assertTrue(service.stat("/gone").isEmpty());
    }

    // ----- helpers -----

    private static ResourceService.WriteRequest rdf(String turtle) {
        return new ResourceService.WriteRequest("text/turtle", turtle.getBytes(StandardCharsets.UTF_8),
                ResourceService.TypeHint.AUTO, null);
    }

    private static ResourceService.WriteRequest container() {
        return new ResourceService.WriteRequest(null, new byte[0],
                ResourceService.TypeHint.CONTAINER, null);
    }
}
