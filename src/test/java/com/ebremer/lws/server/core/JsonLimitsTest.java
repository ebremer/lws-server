package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;
import org.junit.jupiter.api.Test;

/**
 * Finding M17. {@code jakarta.json} parses recursively, so a request body's nesting depth is stack
 * depth: about 24 KB of {@code [[[[…} throws {@link StackOverflowError} inside the parser. An
 * {@code Error} escapes every {@code catch} in the request stack, so the response is aborted with
 * no {@code problem+json} at all — and the endpoints that parse before authorizing let an anonymous
 * client do it.
 *
 * <p>Finding N5 added the other half: the same bound applied to a value the server has just
 * <em>built</em>, because a stored document grows by composition and the byte scan cannot be used
 * on something that has to be serialized before it has bytes.
 *
 * @author Erich Bremer
 */
class JsonLimitsTest {

    /** The depth at which the review measured the parser failing outright. */
    private static final int OVERFLOWING_DEPTH = 4000;

    @Test
    void refusesADocumentNestedPastTheLimit() {
        byte[] deep = nested(JsonLimits.MAX_NESTING_DEPTH + 1);
        LwsException e = assertThrows(LwsException.class, () -> JsonLimits.requireBoundedNesting(deep));
        assertEquals(400, e.status());
    }

    @Test
    void acceptsADocumentAtTheLimit() {
        assertDoesNotThrow(() -> JsonLimits.requireBoundedNesting(nested(JsonLimits.MAX_NESTING_DEPTH)));
    }

    /**
     * The guard has to run before the parser, not around it: the point is that no deep structure is
     * ever built. Each of these would otherwise take the request thread down with an {@code Error}.
     */
    @Test
    void everyPatchEntryPointRefusesADeeplyNestedBodyWithoutParsingIt() {
        byte[] deep = nested(OVERFLOWING_DEPTH);
        assertRefusedBeforeParsing(() -> JsonMergePatch.read(deep));
        assertRefusedBeforeParsing(() -> JsonPatch.read(deep));
        assertRefusedBeforeParsing(() -> JsonPatch.readStructure(deep));
    }

    /**
     * The scan counts brackets, so it has to know which of them are structure. A bracket inside a
     * string literal is data, and a document that is entirely flat must not be refused because its
     * values happen to look like nesting.
     */
    @Test
    void bracketsInsideStringLiteralsDoNotCount() {
        StringBuilder inString = new StringBuilder("{\"a\":\"");
        inString.append("[{".repeat(256));
        inString.append("\"}");
        assertDoesNotThrow(() ->
                JsonLimits.requireBoundedNesting(inString.toString().getBytes(StandardCharsets.UTF_8)));

        // ...and an escaped quote does not end the literal, so what follows is still data.
        String escaped = "{\"a\":\"\\\"" + "[".repeat(128) + "\"}";
        assertDoesNotThrow(() ->
                JsonLimits.requireBoundedNesting(escaped.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * The scan runs over UTF-8 bytes without decoding them, which is only sound because every byte
     * of a multi-byte sequence has its high bit set and so can never be mistaken for a bracket, a
     * quote or an escape. Accented Latin, an em dash, CJK and an astral-plane character between them
     * cover the two-, three- and four-byte forms.
     */
    @Test
    void multiByteCharactersAreNotMistakenForStructure() {
        String doc = "{\"name\":\"café — 日本語 🌍\",\"nested\":{\"ok\":true}}";
        assertDoesNotThrow(() ->
                JsonLimits.requireBoundedNesting(doc.getBytes(StandardCharsets.UTF_8)));
        assertDoesNotThrow(() -> JsonMergePatch.read(doc.getBytes(StandardCharsets.UTF_8)));
    }

    /** The bound is two orders of magnitude above anything real; ordinary documents go straight through. */
    @Test
    void realisticDocumentsAreUnaffected() {
        byte[] merge = "{\"a\":1,\"b\":{\"c\":[1,2,{\"d\":null}]}}".getBytes(StandardCharsets.UTF_8);
        assertDoesNotThrow(() -> JsonMergePatch.read(merge));
        byte[] patch = "[{\"op\":\"add\",\"path\":\"/x\",\"value\":{\"y\":[1,2,3]}}]"
                .getBytes(StandardCharsets.UTF_8);
        assertDoesNotThrow(() -> JsonPatch.read(patch));
    }

    // ----- finding N5: the same bound, applied to a value this server has BUILT -----

    /**
     * The byte scan cannot be reused for a value the server has just built, because obtaining bytes
     * means {@code toString()} and the provider's generator is itself recursive. Measured on this
     * classpath: a tree 1,500 deep serializes happily into 9 KB and then throws
     * {@link StackOverflowError} when it is read back — so serializing to produce something to
     * check would blow the stack on exactly the documents the check exists to refuse.
     *
     * <p>This test builds the deep value <em>iteratively</em> and never serializes it, which is the
     * whole point: the guard has to be reachable on a value whose serialization is not.
     */
    @Test
    void aBuiltValueIsRefusedWithoutEverBeingSerialized() {
        JsonValue deep = JsonValue.EMPTY_JSON_OBJECT;
        for (int i = 0; i < OVERFLOWING_DEPTH; i++) {
            deep = Json.createObjectBuilder().add("a", deep).build();
        }
        JsonValue value = deep;
        LwsException e = assertThrows(LwsException.class, () -> JsonLimits.requireBounded(
                value, JsonLimits.MAX_NESTING_DEPTH, Long.MAX_VALUE, "Stored linkset metadata would be"));
        assertEquals(400, e.status());
        assertTrue(e.getMessage().contains("nested deeper than"), e.getMessage());
    }

    /**
     * The two guards bound the same document at opposite ends, so they must not disagree about what
     * depth means. A one-level drift would mean the server hands out a document it then refuses to
     * be given back.
     */
    @Test
    void theTreeGuardAndTheByteGuardAgreeOnWhatDepthMeans() {
        for (int depth = 1; depth <= JsonLimits.MAX_NESTING_DEPTH + 3; depth++) {
            String json = "[".repeat(depth) + "]".repeat(depth);
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            boolean byteGuardRefused = refuses(() -> JsonLimits.requireBoundedNesting(bytes));
            JsonValue parsed;
            try (JsonReader r = Json.createReader(new StringReader(json))) {
                parsed = r.readValue();
            }
            boolean treeGuardRefused = refuses(() -> JsonLimits.requireBounded(
                    parsed, JsonLimits.MAX_NESTING_DEPTH, Long.MAX_VALUE, "x"));
            assertEquals(byteGuardRefused, treeGuardRefused,
                    "the two guards disagree at depth " + depth);
        }
    }

    /** The size bound is what stops a JSON Patch {@code copy} from doubling a document 60 times. */
    @Test
    void theSizeBoundRefusesAValueTooLargeToStore() {
        JsonArrayBuilder wide = Json.createArrayBuilder();
        for (int i = 0; i < 200; i++) {
            wide.add("0123456789");
        }
        JsonValue value = wide.build();
        LwsException e = assertThrows(LwsException.class,
                () -> JsonLimits.requireBounded(value, JsonLimits.MAX_NESTING_DEPTH, 64, "It would be"));
        assertEquals(400, e.status());
        assertTrue(e.getMessage().contains("larger than"), e.getMessage());
        // ...and the accumulator is a LOWER bound, so anything it accepts really does fit.
        assertDoesNotThrow(() -> JsonLimits.requireBounded(value, JsonLimits.MAX_NESTING_DEPTH,
                value.toString().length(), "It would be"));
    }

    /** UTF-8 length is counted without allocating the encoded form, and must still be exact. */
    @Test
    void utf8LengthMatchesTheRealEncoding() {
        String[] samples = {
            "",
            "abc",
            "café",                                       // two-byte forms
            "日本語",                                       // three-byte forms
            new String(Character.toChars(0x1F30D)),       // four bytes, a surrogate pair
            "a café — 日本語 " + new String(Character.toChars(0x1F30D)) + " z",
        };
        for (String s : samples) {
            assertEquals(s.getBytes(StandardCharsets.UTF_8).length, JsonLimits.utf8Length(s),
                    () -> "utf8Length disagrees for " + s);
        }
    }

    private static boolean refuses(org.junit.jupiter.api.function.Executable action) {
        try {
            action.execute();
            return false;
        } catch (LwsException e) {
            return true;
        } catch (Throwable t) {
            throw new AssertionError("unexpected failure", t);
        }
    }

    /**
     * Asserts the <em>guard</em> refused it, not the {@code StackOverflowError} backstop around the
     * parse. The distinction is the whole finding: catching an {@code Error} thrown by a blown stack
     * is a last resort, not a control — the handler runs on the same exhausted stack, so whether it
     * completes is not something to depend on. Checking for the guard's own message is what pins
     * "the parser never saw these bytes".
     */
    private static void assertRefusedBeforeParsing(org.junit.jupiter.api.function.Executable action) {
        LwsException e = assertThrows(LwsException.class, action);
        assertEquals(400, e.status());
        assertTrue(e.getMessage().contains("nested deeper than"),
                () -> "refused by the parser, not by the depth guard: " + e.getMessage());
    }

    private static byte[] nested(int depth) {
        return ("[".repeat(depth) + "]".repeat(depth)).getBytes(StandardCharsets.UTF_8);
    }
}
