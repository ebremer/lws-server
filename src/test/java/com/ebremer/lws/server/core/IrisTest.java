package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The path-and-IRI arithmetic the whole containment model rests on.
 *
 * <p>{@link Iris} had no test of its own, which is how {@code binaryKey} came to be the raw request
 * path (finding H14) and stayed that way. The cases here are the ones that would have caught it:
 * a client-chosen name that tries to leave its container, one that collapses to nothing, and the
 * two-resources-one-file collision a case-insensitive filesystem produces.
 *
 * @author Erich Bremer
 */
class IrisTest {

    private static final String BASE = "http://example.org";

    // ----- sanitizeSlug: the name a client asked for is not the name it gets -----

    @Test
    void aSlugCannotClimbOutOfItsContainer() {
        // Every separator becomes '-', so no slug can introduce a path segment at all.
        for (String traversal : new String[] {"../..", "..", "../../etc/passwd", "a/b", "/etc/passwd",
                "..\\..\\windows", "%2e%2e%2f"}) {
            String sanitized = Iris.sanitizeSlug(traversal);
            if (sanitized == null) {
                continue; // collapsed to nothing, which is also a refusal
            }
            assertFalse(sanitized.contains("/"), traversal + " -> " + sanitized);
            assertFalse(sanitized.contains("\\"), traversal + " -> " + sanitized);
            assertNotEquals("..", sanitized, traversal);
            assertNotEquals(".", sanitized, traversal);
        }
    }

    @Test
    void aSlugThatIsOnlyDotsOrSeparatorsIsRefused() {
        assertNull(Iris.sanitizeSlug(".."));
        assertNull(Iris.sanitizeSlug("."));
        assertNull(Iris.sanitizeSlug("..."));
        assertNull(Iris.sanitizeSlug(""));
        assertNull(Iris.sanitizeSlug("   "));
        assertNull(Iris.sanitizeSlug("---"));
        assertNull(Iris.sanitizeSlug("/"));
        assertNull(Iris.sanitizeSlug(null));
    }

    @Test
    void anOrdinaryNameSurvivesIntact() {
        assertEquals("notes.txt", Iris.sanitizeSlug("notes.txt"));
        assertEquals("my-file_2", Iris.sanitizeSlug("my-file_2"));
        assertEquals("a-b", Iris.sanitizeSlug("a b"), "a space is a separator, not a deletion");
        assertEquals("a-b", Iris.sanitizeSlug("a///b"), "runs collapse to one");
        // Non-ASCII becomes a separator, and a trailing separator is then trimmed.
        assertEquals("caf", Iris.sanitizeSlug("café"));
        assertEquals("caf-au-lait", Iris.sanitizeSlug("café au lait"));
    }

    /**
     * The trimming happens after the substitution, which is what let {@code "x.acl-"} become the
     * reserved {@code "x.acl"} — the reason C2's guard runs on the composed, sanitized path rather
     * than on the client's raw slug.
     */
    @Test
    void sanitizingCanProduceAReservedName() {
        assertEquals("x.acl", Iris.sanitizeSlug("x.acl-"));
        assertEquals("x.acl", Iris.sanitizeSlug("  x.acl  "));
        assertEquals("x.meta", Iris.sanitizeSlug("x.meta---"));
    }

    // ----- binaryKey: opaque, unique, and not the request path -----

    @Test
    void binaryKeysAreOpaqueAndUnique() {
        Set<String> keys = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            String key = Iris.newBinaryKey();
            assertTrue(keys.add(key), "minted a duplicate binary key: " + key);
            // No separator that could escape the blob root, no reserved Windows device name, and
            // nothing derived from a request path.
            assertFalse(key.contains(".."), key);
            assertFalse(key.startsWith("/"), key);
            assertFalse(key.contains("\\"), key);
        }
    }

    /**
     * Two resources whose IRIs differ only in case are distinct resources with independent ACLs.
     * While keys were path-derived they resolved to one file on NTFS and default APFS, so writing
     * one silently replaced the other's bytes (finding H14).
     */
    @Test
    void twoResourcesDifferingOnlyInCaseGetDifferentKeys() {
        assertNotEquals(Iris.newBinaryKey(), Iris.newBinaryKey());
    }

    // ----- the containment arithmetic -----

    @Test
    void parentPathAlwaysEndsInASlashAndStopsAtTheRoot() {
        assertEquals("/", Iris.parentPath("/doc"));
        assertEquals("/", Iris.parentPath("/c/"));
        assertEquals("/c/", Iris.parentPath("/c/doc"));
        assertEquals("/c/d/", Iris.parentPath("/c/d/e/"));
        assertNull(Iris.parentPath("/"), "the root has no parent");
    }

    @Test
    void containerPathsAreExactlyThoseEndingInASlash() {
        assertTrue(Iris.isContainerPath("/"));
        assertTrue(Iris.isContainerPath("/c/"));
        assertFalse(Iris.isContainerPath("/c"));
        assertTrue(Iris.isRoot("/"));
        assertFalse(Iris.isRoot("/c/"));
    }

    @Test
    void pathAndIriRoundTripThroughTheBase() {
        assertEquals(BASE + "/c/doc", Iris.toIri(BASE, "/c/doc"));
        assertEquals(BASE + "/c/doc", Iris.toIri(BASE + "/", "/c/doc"));
        assertEquals("/c/doc", Iris.toPath(BASE, BASE + "/c/doc"));
        assertNull(Iris.toPath(BASE, "https://elsewhere.example/c/doc"),
                "an IRI outside the base has no path here — callers must not treat null as the root");
    }

    @Test
    void reservedSuffixesAreRecognisedInEitherCase() {
        assertTrue(Iris.hasReservedSuffix("/x.acl"));
        assertTrue(Iris.hasReservedSuffix("/x.meta"));
        assertTrue(Iris.isAclPath("/x.acl"));
        assertTrue(Iris.isLinksetPath("/x.meta"));
        assertEquals("/x", Iris.linksetTargetPath("/x.meta"));
        assertFalse(Iris.hasReservedSuffix("/x.acl-2"));
    }

    @Test
    void isWithinIsNotAPrefixMatch() {
        assertTrue(Iris.isWithin("/c/", "/c/doc"));
        assertTrue(Iris.isWithin("/c/", "/c/d/deep"));
        assertFalse(Iris.isWithin("/c/", "/c"), "the container is not within itself");
        assertFalse(Iris.isWithin("/c/", "/cc/doc"),
                "a sibling whose name merely starts the same is not contained");
    }
}
