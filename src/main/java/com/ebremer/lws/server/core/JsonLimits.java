package com.ebremer.lws.server.core;

import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;
import java.util.Iterator;
import jakarta.json.JsonValue;

/**
 * The bound that makes it safe to hand an untrusted request body to a JSON parser.
 *
 * <p>{@code jakarta.json}'s reader descends recursively, so nesting depth is stack depth. Measured
 * on this classpath, a body nested 2000 deep parses, and one nested 4000 deep — about 24 KB of
 * {@code [[[[…}, far under any request-size cap — throws {@link StackOverflowError} during the
 * parse. Being an {@link Error} rather than an exception it escapes every {@code catch} in the
 * request stack, so the response is aborted with no {@code problem+json} and no status; and on the
 * paths that parse before authorizing, an anonymous client can do it.
 *
 * <p>The guard therefore runs <em>before</em> the parser sees the bytes: a single non-recursive scan
 * refuses the document outright, so no deep structure is ever built. Callers keep a
 * {@code StackOverflowError} in their {@code catch} as a backstop, to convert it into a {@code 400}
 * if one ever arrives by a route this does not cover.
 *
 * @author Erich Bremer
 */
public final class JsonLimits {

    /**
     * Maximum object/array nesting accepted in a request body.
     *
     * <p>Two orders of magnitude below the measured failure point, and far above anything real. The
     * deepest document this server generates for itself is its own JSON-LD projection of a stored
     * graph, which measures depth 3–4 whatever the graph contains: Jena flattens into {@code @graph}
     * rather than nesting, so a 500-element {@code rdf:List} and a 500-link blank-node chain both
     * come out at depth 3 and 4 respectively. Nothing legitimate approaches this.
     */
    public static final int MAX_NESTING_DEPTH = 64;

    private static final byte QUOTE = '"';
    private static final byte BACKSLASH = (byte) 92;

    private JsonLimits() {
    }

    /**
     * Refuse a JSON document nested deeper than {@link #MAX_NESTING_DEPTH}, before parsing it.
     *
     * <p>Counts brackets outside string literals, which is enough: a document that opens more than
     * the limit is refused whether or not the rest of it is well-formed, and one that never does
     * cannot make the parser recurse further than the limit. UTF-8 needs no decoding here — every
     * byte of a multi-byte sequence has its high bit set, so none can be mistaken for a bracket, a
     * quote or an escape.
     */
    public static void requireBoundedNesting(byte[] json) {
        requireBoundedNesting(json, MAX_NESTING_DEPTH);
    }

    /**
     * The same scan over a document already in hand as a {@code String} — a stored literal, say —
     * without copying it into a byte array first.
     *
     * <p>Sound for the same reason the byte scan is: every char of a non-ASCII code point is
     * outside the ASCII range, so none can be mistaken for a bracket, a quote or an escape.
     */
    public static void requireBoundedNesting(CharSequence json, int maxDepth) {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            switch (c) {
                case '"' -> inString = true;
                case '{', '[' -> {
                    if (++depth > maxDepth) {
                        throw LwsException.badRequest(
                                "JSON nested deeper than " + maxDepth + " levels");
                    }
                }
                case '}', ']' -> depth--;
                default -> { }
            }
        }
    }

    /**
     * Refuse a JSON <em>value this server has just built</em> whose nesting exceeds {@code maxDepth}
     * or whose serialized form would exceed {@code maxBytes}.
     *
     * <p>The byte scan above cannot be used for this. Obtaining bytes means calling
     * {@code toString()}, and the {@code jakarta.json} implementation writes a value tree
     * recursively — measured on this classpath, a tree 1,500 deep serializes without complaint into
     * 9 KB and then throws {@link StackOverflowError} when it is read back. So serializing to
     * produce something to check would overflow on exactly the documents this exists to refuse.
     * This walks the tree with an explicit stack of iterators instead: nothing recurses, and the
     * stack holds one frame per open container, so at most {@code maxDepth} of them.
     *
     * <p>Depth is counted exactly as the byte scan counts it — each enclosing object or array is one
     * level, so <code>{}</code> is depth 1 — because the two guard the same document at opposite
     * ends and must not disagree about it.
     *
     * <p>The size accumulator is a deliberate <em>lower bound</em> on the serialized length: every
     * structural character is counted, a string contributes its UTF-16 length (never more than its
     * UTF-8 length) plus its quotes, and escapes are ignored. Undercounting is the safe direction —
     * it can never refuse a document whose real serialization is inside the limit — and it lets the
     * walk fail <em>before</em> the {@code toString()} that would otherwise have to allocate it.
     */
    public static void requireBounded(JsonValue value, int maxDepth, long maxBytes, String what) {
        if (value == null) {
            return;
        }
        Deque<Iterator<? extends JsonValue>> frames = new ArrayDeque<>();
        Deque<Iterator<String>> names = new ArrayDeque<>();
        JsonValue current = value;
        long size = 0;
        for (;;) {
            size += costOf(current);
            if (size > maxBytes) {
                throw LwsException.badRequest(what + " larger than " + maxBytes + " bytes");
            }
            Collection<JsonValue> children = switch (current.getValueType()) {
                case OBJECT -> current.asJsonObject().values();
                case ARRAY -> current.asJsonArray();
                default -> null;
            };
            if (children != null) {
                if (frames.size() + 1 > maxDepth) {
                    throw LwsException.badRequest(
                            what + " nested deeper than " + maxDepth + " levels");
                }
                if (current.getValueType() == JsonValue.ValueType.OBJECT) {
                    // Member names are part of the serialized length and can dominate it.
                    for (String name : current.asJsonObject().keySet()) {
                        size += name.length() + 3; // two quotes and a colon
                        if (size > maxBytes) {
                            throw LwsException.badRequest(
                                    what + " larger than " + maxBytes + " bytes");
                        }
                    }
                }
                frames.push(children.iterator());
            }
            while (!frames.isEmpty() && !frames.peek().hasNext()) {
                frames.pop();
            }
            if (frames.isEmpty()) {
                return;
            }
            current = frames.peek().next();
        }
    }

    /**
     * A lower bound on what one value contributes to its own serialization, excluding its children.
     *
     * <p>Separating commas are deliberately not counted, and neither is the extra length a string
     * gains from escaping. Both only ever make the real document <em>longer</em>, so leaving them
     * out keeps this a bound that can never refuse a document which would in fact have fit.
     */
    private static long costOf(JsonValue value) {
        return switch (value.getValueType()) {
            case OBJECT, ARRAY -> 2;                                          // the two brackets
            case STRING -> ((jakarta.json.JsonString) value).getString().length() + 2; // and quotes
            case NUMBER -> value.toString().length();
            default -> 4;                                                     // true / false / null
        };
    }

    /** The exact UTF-8 length of a string, without allocating the encoded form to measure it. */
    public static long utf8Length(String s) {
        long n = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x80) {
                n += 1;
            } else if (c < 0x800) {
                n += 2;
            } else if (Character.isHighSurrogate(c) && i + 1 < s.length()
                    && Character.isLowSurrogate(s.charAt(i + 1))) {
                n += 4;
                i++;
            } else {
                n += 3;
            }
        }
        return n;
    }

    private static void requireBoundedNesting(byte[] json, int maxDepth) {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (byte b : json) {
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (b == BACKSLASH) {
                    escaped = true;
                } else if (b == QUOTE) {
                    inString = false;
                }
                continue;
            }
            switch (b) {
                case QUOTE -> inString = true;
                case '{', '[' -> {
                    if (++depth > maxDepth) {
                        throw LwsException.badRequest(
                                "JSON nested deeper than " + maxDepth + " levels");
                    }
                }
                case '}', ']' -> depth--;
                default -> { }
            }
        }
    }
}
