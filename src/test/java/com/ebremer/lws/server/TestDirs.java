package com.ebremer.lws.server;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;

/**
 * Temporary data directories for tests, cleaned up as well as this platform allows.
 *
 * <p>The suite used to call {@link Files#createTempDirectory} directly and never remove the result.
 * Each one holds a TDB2 dataset, so they are not small: on one machine the leak reached 1,671
 * directories and filled the disk, and the symptom was not a disk error but TDB2 failing in
 * {@code @BeforeAll} with {@code BlockMgrMapped.segmentAllocate: Segment = 0}, which reads like a
 * bug in this code rather than "you are out of space".
 *
 * <p><strong>Why not {@code @TempDir}.</strong> That is the obvious answer and it does not work
 * here. TDB2 memory-maps its files, and Windows refuses to delete a mapped file while the mapping
 * exists — Java gives no way to force an unmap, and the mapping outlives {@code close()} until the
 * buffers are collected. JUnit's cleanup therefore throws and fails the class it was trying to tidy
 * up after: converting the suite to {@code @TempDir} turned fourteen green classes into fourteen
 * "Failed to close extension context" errors.
 *
 * <p>So the deletion is moved to where it can succeed: <strong>the next run</strong>. Each JVM
 * sweeps what previous runs left behind — by then those processes are gone and their mappings with
 * them — then creates its own directory and makes a best-effort attempt at its own on exit. The
 * accumulation is bounded at roughly one run's worth instead of growing without limit, which is the
 * property that actually matters.
 *
 * @author Erich Bremer
 */
public final class TestDirs {

    /** Prefix for every directory this class creates, so a sweep can recognise its own. */
    private static final String PREFIX = "lws-test-";

    private static final List<Path> CREATED = new CopyOnWriteArrayList<>();

    static {
        sweepPreviousRuns();
        Runtime.getRuntime().addShutdownHook(new Thread(TestDirs::deleteOurs, "lws-test-dir-cleanup"));
    }

    private TestDirs() {
    }

    /** A fresh temporary directory for one test class (or one test) to use as its data dir. */
    public static Path create() {
        try {
            Path dir = Files.createTempDirectory(PREFIX);
            CREATED.add(dir);
            return dir;
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot create a temporary test directory", e);
        }
    }

    /** Delete what earlier runs left behind; their file mappings died with their processes. */
    private static void sweepPreviousRuns() {
        Path tmp = Path.of(System.getProperty("java.io.tmpdir"));
        try (Stream<Path> entries = Files.list(tmp)) {
            entries.filter(Files::isDirectory)
                    .filter(p -> p.getFileName().toString().startsWith(PREFIX))
                    .forEach(TestDirs::deleteQuietly);
        } catch (IOException | RuntimeException e) {
            // A sweep is an optimisation, never a reason to fail a test run.
        }
    }

    private static void deleteOurs() {
        CREATED.forEach(TestDirs::deleteQuietly);
    }

    /**
     * Recursively delete, ignoring anything still held open. On Windows the TDB2 files usually are,
     * which is the whole reason this is best-effort: what it cannot remove now, the next run's sweep
     * removes then.
     */
    private static void deleteQuietly(Path dir) {
        try (Stream<Path> paths = Files.walk(dir)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // Still mapped, or still open. The next run will get it.
                }
            });
        } catch (IOException | RuntimeException ignored) {
            // Gone already, or unreadable. Either way there is nothing useful to do here.
        }
    }
}
