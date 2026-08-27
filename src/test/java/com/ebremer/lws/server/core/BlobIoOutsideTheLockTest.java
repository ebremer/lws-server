package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
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
import com.ebremer.lws.server.storage.BinaryStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;

/**
 * Finding N2 — no blob I/O happens while the store's single writer lock is held.
 *
 * <p>The binary store is a filesystem, and TDB2 admits one writer for the whole storage. Streaming
 * up to {@code lws.max-request-bytes} — 64 MiB by default — into it from inside the write callback
 * made every other write in the server wait for a file copy, and on an NFS or SMB data directory for
 * network I/O. The patch paths were worse: they read the whole stored blob, parsed it, applied the
 * patch and wrote the result, all under the lock.
 *
 * <p>None of it needs the lock. The key is freshly minted so no reader can reach it, and
 * {@code BlobChanges} already existed to unlink a staged key if the transaction aborts. What does
 * need the lock is the quota comparison and — for the patch paths — proof that the bytes the patch
 * was computed from are still the stored ones, which {@code requireUnchangedContent} supplies.
 *
 * @author Erich Bremer
 */
class BlobIoOutsideTheLockTest {

    private static final String BASE = "http://example.org";
    private static final LwsPrincipal ALICE = new LwsPrincipal("https://alice.example/#me", null, null);

    private RdfStore store;
    private ResourceService service;
    private WatchfulBlobs blobs;
    private Path blobRoot;

    /** Records every blob operation, and above all whether any of them ran under the writer lock. */
    private static final class WatchfulBlobs implements BinaryStore {

        private final BinaryStore delegate;
        private RdfStore store;
        private final List<String> underTheLock = new ArrayList<>();

        WatchfulBlobs(BinaryStore delegate) {
            this.delegate = delegate;
        }

        private void check(String what) {
            if (store != null && store.inUnitOfWork()) {
                underTheLock.add(what);
            }
        }

        @Override
        public StoredBlob write(String key, InputStream in) throws IOException {
            check("write " + key);
            return delegate.write(key, in);
        }

        @Override
        public InputStream read(String key) throws IOException {
            check("read " + key);
            return delegate.read(key);
        }

        @Override
        public void delete(String key) throws IOException {
            check("delete " + key);
            delegate.delete(key);
        }

        @Override
        public long size(String key) throws IOException {
            check("size " + key);
            return delegate.size(key);
        }

        @Override
        public boolean exists(String key) {
            check("exists " + key);
            return delegate.exists(key);
        }
    }

    @BeforeEach
    void setUp(@TempDir Path dir) {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        p.setProperty("lws.data-dir", dir.toString());
        LwsConfiguration config = LwsConfiguration.of(p);
        store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        blobRoot = config.blobDir();
        blobs = new WatchfulBlobs(new FileSystemBinaryStore(blobRoot));
        blobs.store = store;
        service = new ResourceService(store, blobs, new ResourceRegistry(),
                (principal, iri, mode) -> true, config, Clock.systemUTC());
        service.ensureStorageRoot();
    }

    @Test
    void noBlobIoHappensInsideAUnitOfWorkOnAnyWritePath() throws Exception {
        service.put("/doc.json", ALICE, json("{\"a\":1}"));
        // A replace must name the version it replaces, so it carries the tag it just got.
        service.put("/doc.json", ALICE, json("{\"a\":2}"), IfMatch.of(etagOf("/doc.json")));
        service.create("/", ALICE, json("{\"b\":1}"));                          // POST
        service.patch("/doc.json", ALICE, "{\"c\":3}".getBytes(StandardCharsets.UTF_8),
                "application/merge-patch+json", IfMatch.of(etagOf("/doc.json")));
        service.patch("/doc.json", ALICE,
                "[{\"op\":\"add\",\"path\":\"/d\",\"value\":4}]".getBytes(StandardCharsets.UTF_8),
                "application/json-patch+json", IfMatch.of(etagOf("/doc.json")));
        service.delete("/doc.json", ALICE);

        assertTrue(blobs.underTheLock.isEmpty(),
                () -> "blob I/O ran while the store writer lock was held: " + blobs.underTheLock);
    }

    /** The hoist must not change what the patch paths actually produce. */
    @Test
    void patchingStillProducesTheRightBytes() throws Exception {
        service.put("/doc.json", ALICE, json("{\"a\":1}"));

        service.patch("/doc.json", ALICE, "{\"b\":2}".getBytes(StandardCharsets.UTF_8),
                "application/merge-patch+json", IfMatch.of(etagOf("/doc.json")));
        assertEquals("{\"a\":1,\"b\":2}", content("/doc.json"));

        service.patch("/doc.json", ALICE,
                "[{\"op\":\"replace\",\"path\":\"/a\",\"value\":9}]".getBytes(StandardCharsets.UTF_8),
                "application/json-patch+json", IfMatch.of(etagOf("/doc.json")));
        assertEquals("{\"a\":9,\"b\":2}", content("/doc.json"));
    }

    /**
     * A refused write leaves no bytes behind — and this counts them, because the obvious version of
     * this test does not.
     *
     * <p>The first version PUT a container body, which resolves to {@code CONTAINER} and therefore
     * stages nothing at all: it asserted about a scenario in which the code under test never ran,
     * and would have passed with the sweep deleted outright. It also only checked that an unrelated
     * resource was undisturbed, never looking in the blob store.
     *
     * <p>What actually leaked was every refusal between staging the bytes and registering the key,
     * and the registration used to happen inside the transaction, after the authorization check. So
     * the scenarios that matter are the ordinary ones: a denial, and a stale precondition. Measured
     * against the unfixed code, five refused conditional PUTs of 1 MiB grew the store by 10 MB.
     */
    @Test
    void aRefusedWriteLeavesNoStagedBytesBehind() throws Exception {
        service.put("/doc.json", ALICE, json("{\"a\":1}"));
        int baseline = blobCount();

        // A stale If-Match: the ordinary failure mode, since a replace MUST carry a precondition.
        for (int i = 0; i < 5; i++) {
            LwsException refused = assertThrows(LwsException.class, () -> service.put(
                    "/doc.json", ALICE, json("{\"a\":2}"), IfMatch.of("\"stale\"")));
            assertEquals(412, refused.status());
        }
        assertEquals(baseline, blobCount(), "a refused conditional PUT left its bytes on disk");

        // A type change: refused with 409, after the body has been staged.
        LwsException conflict = assertThrows(LwsException.class, () -> service.put("/doc.json", ALICE,
                new ResourceService.WriteRequest("text/turtle",
                        "<#it> <http://schema.org/name> \"v\" .".getBytes(StandardCharsets.UTF_8),
                        ResourceService.TypeHint.RDF_SOURCE, null),
                IfMatch.of(etagOf("/doc.json"))));
        assertEquals(409, conflict.status());
        assertEquals(baseline, blobCount(), "a refused type change left its bytes on disk");

        // A refused PATCH, whose result is staged before the transaction opens.
        LwsException patchRefused = assertThrows(LwsException.class, () -> service.patch("/doc.json",
                ALICE, "{\"b\":2}".getBytes(StandardCharsets.UTF_8),
                "application/merge-patch+json", IfMatch.of("\"stale\"")));
        assertEquals(412, patchRefused.status());
        assertEquals(baseline, blobCount(), "a refused PATCH left its bytes on disk");

        assertEquals("{\"a\":1}", content("/doc.json"), "none of that should have changed the resource");
    }

    /** How many blobs the store holds, counted from the filesystem rather than from the registry. */
    private int blobCount() throws IOException {
        try (java.util.stream.Stream<Path> walk = java.nio.file.Files.walk(blobRoot)) {
            return (int) walk.filter(java.nio.file.Files::isRegularFile).count();
        }
    }

    private static ResourceService.WriteRequest json(String body) {
        return new ResourceService.WriteRequest("application/json", body.getBytes(StandardCharsets.UTF_8), null, null);
    }

    private String etagOf(String path) {
        return service.stat(path).orElseThrow().etag();
    }

    private String content(String path) throws IOException {
        return new String(contentBytes(path), StandardCharsets.UTF_8);
    }

    private byte[] contentBytes(String path) throws IOException {
        try (InputStream in = service.openBinary(service.stat(path).orElseThrow())) {
            return in.readAllBytes();
        }
    }
}
