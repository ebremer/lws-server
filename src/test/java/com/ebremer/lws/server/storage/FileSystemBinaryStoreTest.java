package com.ebremer.lws.server.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.TestDirs;

/**
 * {@link FileSystemBinaryStore} — one of the four classes the review found to have no test at all,
 * and the one that owns every byte of every non-RDF resource this server stores.
 *
 * <p>Two properties matter more than the round trip. The first is <strong>containment</strong>: all
 * five entry points funnel through a single private {@code resolve(String)} that refuses a key
 * resolving outside the base, so the guard exists in exactly one place and a test that only checked
 * {@code read} would not notice a sixth method added past it. Keys are opaque and server-minted
 * today ({@code Iris.newBinaryKey}, after finding H14 stopped them being request paths), but the
 * store is the last line and is tested here as though the key were hostile.
 *
 * <p>The second is <strong>atomicity</strong>: a write goes to a temporary file and is promoted by a
 * single {@code Files.move}, so a client that disconnects mid-upload must leave the previous bytes
 * intact and nothing else behind. That is the only reason the {@code finally} in {@code write}
 * exists, and {@link #aFailedWriteLeavesTheOldContentAndNoTemporaryFile()} is the only thing that
 * runs it.
 *
 * @author Erich Bremer
 */
class FileSystemBinaryStoreTest {

    /**
     * A fresh directory per test method (JUnit's default per-method lifecycle), so the
     * "exactly one file in the tree" assertions below have a tree of their own. {@code @TempDir}
     * is used nowhere in this suite — see {@link TestDirs} for why, and for who deletes these.
     */
    private final Path base = TestDirs.create().resolve("blobs");

    /** Keys that normalise outside the base on every platform this build runs on. */
    private static final List<String> ESCAPING_KEYS =
            List.of("../escape", "a/../../escape", "/absolute", "../");

    private static final String MID_UPLOAD_FAILURE = "the client connection dropped mid-upload";

    // ----- the round trip -----

    @Test
    void writeRoundTripsAndReportsSizeAndSha256() throws Exception {
        FileSystemBinaryStore store = new FileSystemBinaryStore(base);
        byte[] bytes = "hello".getBytes(StandardCharsets.UTF_8);

        // A nested key: the caller never creates anything, so write must build the intermediate
        // directories itself.
        BinaryStore.StoredBlob blob = store.write("a/b/c.bin", new ByteArrayInputStream(bytes));

        String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        assertEquals(5L, blob.size());
        assertEquals(expected, blob.sha256Hex());
        assertEquals(64, blob.sha256Hex().length(), "SHA-256, not some shorter digest");
        assertEquals(blob.sha256Hex().toLowerCase(Locale.ROOT), blob.sha256Hex(),
                "lower-case hex: the digest is compared literally against the stored triple");

        assertTrue(store.exists("a/b/c.bin"));
        assertEquals(5L, store.size("a/b/c.bin"));
        try (InputStream in = store.read("a/b/c.bin")) {
            assertArrayEquals(bytes, in.readAllBytes());
        }
        assertFalse(store.exists("a/b"),
                "an intermediate directory is not a blob; exists() asks for a regular file");
    }

    // ----- containment -----

    /**
     * Every entry point, not just the obvious one. The check lives in one private helper, so this
     * asserts that all five actually call it — the failure this pins is a refactor that inlines the
     * resolve into four of them and forgets the fifth.
     */
    @Test
    void everyEntryPointRefusesAKeyThatEscapesTheRoot() throws Exception {
        FileSystemBinaryStore store = new FileSystemBinaryStore(base);
        store.write("inside.bin", new ByteArrayInputStream("x".getBytes(StandardCharsets.UTF_8)));

        for (String key : ESCAPING_KEYS) {
            assertThrows(IllegalArgumentException.class, () -> store.exists(key), "exists: " + key);
            assertThrows(IllegalArgumentException.class, () -> store.read(key), "read: " + key);
            assertThrows(IllegalArgumentException.class,
                    () -> store.write(key, new ByteArrayInputStream(new byte[] {1})), "write: " + key);
            assertThrows(IllegalArgumentException.class, () -> store.delete(key), "delete: " + key);
            assertThrows(IllegalArgumentException.class, () -> store.size(key), "size: " + key);
        }

        assertFalse(Files.exists(base.getParent().resolve("escape")),
                "a refused key still created something outside the blob root");
        assertTrue(store.exists("inside.bin"),
                "the refusals must not have disturbed a legitimate blob");
    }

    /**
     * The five-way check above is only complete while there are five entry points. This fails the
     * moment a sixth public method takes a key, which is the prompt to extend that list rather than
     * to ship an unchecked path into the blob tree.
     */
    @Test
    void theStoreHasNoEntryPointBeyondTheFiveTheEscapeTestCovers() {
        List<String> keyed = Arrays.stream(FileSystemBinaryStore.class.getDeclaredMethods())
                .filter(m -> Modifier.isPublic(m.getModifiers()))
                .filter(m -> m.getParameterCount() > 0 && m.getParameterTypes()[0] == String.class)
                .map(Method::getName)
                .distinct()
                .sorted()
                .toList();
        assertEquals(List.of("delete", "exists", "read", "size", "write"), keyed,
                "a public method now takes a key: add it to everyEntryPointRefusesAKeyThatEscapesTheRoot");
    }

    /**
     * The base is {@code …/blobs}; {@code …/blobs-evil} shares its entire string prefix but not its
     * path components. {@link Path#startsWith(Path)} is a component-wise test, so this is refused
     * today — the test exists so it stays a component test and is never "simplified" into a
     * {@code String.startsWith}, which is the classic way this guard is rewritten and broken.
     */
    @Test
    void aSiblingDirectoryWithASharedPrefixIsNotInside() {
        FileSystemBinaryStore store = new FileSystemBinaryStore(base);
        String key = "../" + base.getFileName() + "-evil/f";

        assertThrows(IllegalArgumentException.class, () -> store.exists(key));
        assertThrows(IllegalArgumentException.class, () -> store.read(key));
        assertThrows(IllegalArgumentException.class,
                () -> store.write(key, new ByteArrayInputStream(new byte[] {1})));
        assertThrows(IllegalArgumentException.class, () -> store.delete(key));
        assertThrows(IllegalArgumentException.class, () -> store.size(key));
    }

    /**
     * A backslash separates path components on Windows and is an ordinary filename character
     * elsewhere, so {@code "..\\escape"} leaves the root on one platform and names a file inside it
     * on the other. The assumption asks the platform rather than the OS name: wherever the backslash
     * does separate, the key must be refused.
     */
    @Test
    void aBackslashKeyIsRefusedWhereTheBackslashSeparatesPathComponents() {
        Assumptions.assumeTrue(Path.of("..\\escape").getNameCount() > 1,
                "this platform treats a backslash as an ordinary filename character");
        FileSystemBinaryStore store = new FileSystemBinaryStore(base);

        assertThrows(IllegalArgumentException.class, () -> store.exists("..\\escape"));
        assertThrows(IllegalArgumentException.class, () -> store.read("..\\escape"));
        assertThrows(IllegalArgumentException.class,
                () -> store.write("..\\escape", new ByteArrayInputStream(new byte[] {1})));
        assertThrows(IllegalArgumentException.class, () -> store.delete("..\\escape"));
        assertThrows(IllegalArgumentException.class, () -> store.size("..\\escape"));
    }

    // ----- atomicity -----

    @Test
    void replacingABlobLeavesNoTemporaryFile() throws Exception {
        FileSystemBinaryStore store = new FileSystemBinaryStore(base);

        BinaryStore.StoredBlob first = store.write("dup.bin",
                new ByteArrayInputStream("v1".getBytes(StandardCharsets.UTF_8)));
        BinaryStore.StoredBlob second = store.write("dup.bin",
                new ByteArrayInputStream("second version".getBytes(StandardCharsets.UTF_8)));

        assertNotEquals(first.sha256Hex(), second.sha256Hex(),
                "the digest is of the content, not of the key");
        assertEquals(14L, second.size());
        try (InputStream in = store.read("dup.bin")) {
            assertEquals("second version", new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        assertEquals(List.of("dup.bin"), namesIn(base),
                "the write-to-temp-then-move left a .lws-*.tmp behind");
    }

    /**
     * The only test that runs the {@code finally} in {@code write}. A client that disconnects
     * mid-upload must leave the previous bytes readable — the temporary file is only promoted by an
     * atomic move that never happens here — and must leave no partial file for the next
     * {@code Files.list} of that directory to trip over.
     */
    @Test
    void aFailedWriteLeavesTheOldContentAndNoTemporaryFile() throws Exception {
        FileSystemBinaryStore store = new FileSystemBinaryStore(base);
        store.write("kept.bin", new ByteArrayInputStream("v1".getBytes(StandardCharsets.UTF_8)));

        IOException thrown = assertThrows(IOException.class,
                () -> store.write("kept.bin", failsAfterOneChunk()));
        assertEquals(MID_UPLOAD_FAILURE, thrown.getMessage(),
                "the upload's own failure must reach the caller, not be reshaped into another");

        try (InputStream in = store.read("kept.bin")) {
            assertEquals("v1", new String(in.readAllBytes(), StandardCharsets.UTF_8),
                    "a failed replacement destroyed the bytes it failed to replace");
        }
        assertEquals(2L, store.size("kept.bin"));
        assertEquals(List.of("kept.bin"), namesIn(base),
                "a partial upload was left in the blob tree");
    }

    // ----- absence -----

    /** {@code deleteIfExists}: a DELETE the client retries, or one racing another, is not an error. */
    @Test
    void deletingAMissingKeyIsNotAnError() throws Exception {
        FileSystemBinaryStore store = new FileSystemBinaryStore(base);
        assertDoesNotThrow(() -> store.delete("never-written.bin"));
        assertFalse(store.exists("never-written.bin"));

        store.write("gone.bin", new ByteArrayInputStream("x".getBytes(StandardCharsets.UTF_8)));
        assertTrue(store.exists("gone.bin"));
        store.delete("gone.bin");
        assertFalse(store.exists("gone.bin"));
        assertDoesNotThrow(() -> store.delete("gone.bin"));
    }

    /**
     * Absent and empty are different answers. A caller that could not tell them apart would serve a
     * missing blob as a zero-length representation instead of failing.
     */
    @Test
    void aMissingKeyIsNotReadableAndHasNoSizeWhereasAnEmptyBlobHasBoth() throws Exception {
        FileSystemBinaryStore store = new FileSystemBinaryStore(base);
        assertThrows(NoSuchFileException.class, () -> store.size("nope.bin"));
        assertThrows(NoSuchFileException.class, () -> store.read("nope.bin"));
        assertFalse(store.exists("nope.bin"));

        assertEquals(0L, store.write("empty.bin", new ByteArrayInputStream(new byte[0])).size());
        assertEquals(0L, store.size("empty.bin"));
        assertTrue(store.exists("empty.bin"), "a zero-length blob still exists");
    }

    // ----- construction -----

    @Test
    void theConstructorCreatesTheWholeDirectoryTree() {
        Path deep = base.resolve("does/not/exist/yet");
        assertFalse(Files.exists(deep));

        new FileSystemBinaryStore(deep);

        assertTrue(Files.isDirectory(deep),
                "a first start must not require the operator to create the blob tree by hand");
    }

    // ----- helpers -----

    private static List<String> namesIn(Path dir) throws IOException {
        try (Stream<Path> entries = Files.list(dir)) {
            return entries.map(p -> p.getFileName().toString()).sorted().toList();
        }
    }

    /** A stream that yields one short chunk and then fails, the way a dropped upload does. */
    private static InputStream failsAfterOneChunk() {
        return new InputStream() {

            private boolean chunkDelivered;

            @Override
            public int read() throws IOException {
                byte[] one = new byte[1];
                int n = read(one, 0, 1);
                return n < 0 ? -1 : one[0] & 0xff;
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (chunkDelivered) {
                    throw new IOException(MID_UPLOAD_FAILURE);
                }
                chunkDelivered = true;
                int n = Math.min(3, len);
                for (int i = 0; i < n; i++) {
                    b[off + i] = 'p';
                }
                return n;
            }
        };
    }
}
