package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * The entity-tag comparator that conditional writes turn on.
 *
 * <p>It is worth pinning on its own because four call sites now share it — the servlet's
 * {@code If-Match} pre-check, the compare-and-swap inside {@code ResourceService}'s write
 * transactions, {@code LinksetService}'s, and both {@code If-None-Match} paths — and they replaced
 * three separately hand-rolled dialects of the same comparison.
 *
 * @author Erich Bremer
 */
class IfMatchTest {

    private static final LwsResource DOC = new LwsResource("http://example.org/doc",
            ResourceType.RDF_SOURCE, "http://example.org/", Instant.EPOCH, Instant.EPOCH,
            "abc123", "text/turtle", -1, null, null, null);

    @Test
    void absentPreconditionIsSatisfiedByAnythingIncludingAbsence() {
        IfMatch none = IfMatch.of(null);
        assertFalse(none.isPresent());
        assertTrue(none.satisfiedBy(DOC));
        assertTrue(none.satisfiedBy(null), "an unconditional PUT still creates");
    }

    @Test
    void acceptsBothTheQuotedAndTheBareForm() {
        assertTrue(IfMatch.of("\"abc123\"").satisfiedBy(DOC));
        assertTrue(IfMatch.of("abc123").satisfiedBy(DOC));
        assertTrue(IfMatch.of("  \"abc123\"  ").satisfiedBy(DOC));
        assertFalse(IfMatch.of("\"deadbeef\"").satisfiedBy(DOC));
    }

    @Test
    void acceptsAListAndTheWeakFormThisServerNeverEmits() {
        assertTrue(IfMatch.of("\"x\", \"abc123\", \"y\"").satisfiedBy(DOC));
        assertTrue(IfMatch.of("W/\"abc123\"").satisfiedBy(DOC));
        assertFalse(IfMatch.of("\"x\", \"y\"").satisfiedBy(DOC));
    }

    @Test
    void starRequiresTheResourceToExist() {
        assertTrue(IfMatch.of("*").satisfiedBy(DOC));
        // RFC 9110 13.1.1: "*" is false when the origin server has no current representation.
        assertFalse(IfMatch.of("*").satisfiedBy(null));
        // ... and it matches a resource that exists but carries no tag of its own.
        assertTrue(IfMatch.of("*").matches(null));
    }

    @Test
    void noPreconditionIsEverSatisfiedByAResourceThatDoesNotExist() {
        assertFalse(IfMatch.of("\"abc123\"").satisfiedBy(null));
        assertFalse(IfMatch.of("*").satisfiedBy(null));
    }

    /**
     * A present-but-empty header is malformed, and must not decay into "no precondition at all" —
     * that would answer it with an unconditional write, the one thing a client that sent the header
     * cannot have meant.
     */
    @Test
    void anEmptyHeaderIsPresentAndMatchesNothing() {
        for (String malformed : new String[] { "", "   ", ",", " , " }) {
            IfMatch empty = IfMatch.of(malformed);
            assertTrue(empty.isPresent(), "[" + malformed + "] must count as a precondition");
            assertFalse(empty.satisfiedBy(DOC), "[" + malformed + "] must match no tag");
        }
    }

    @Test
    void aResourceWithNoTagMatchesOnlyStar() {
        LwsResource untagged = DOC.withEtag(null);
        assertFalse(IfMatch.of("\"abc123\"").satisfiedBy(untagged));
        assertTrue(IfMatch.of("*").satisfiedBy(untagged));
    }
}
