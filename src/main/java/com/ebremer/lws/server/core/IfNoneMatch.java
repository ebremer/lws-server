package com.ebremer.lws.server.core;

/**
 * A client's {@code If-None-Match} precondition on a <em>write</em>, carried into the transaction
 * that has to honour it.
 *
 * <p>The header was never evaluated on a write at all, which made create-only {@code PUT} — the
 * ordinary way to claim a name without risking an overwrite — impossible to express: a client that
 * sent {@code If-None-Match: *} had it ignored and replaced whatever was there (finding L28). RFC
 * 9110 &sect;13.1.2 defines it as the negation of {@code If-Match}: the request proceeds only when
 * <em>no</em> current representation matches, and {@code *} matches any existing one, so
 * {@code If-None-Match: *} means "only if this does not exist yet".
 *
 * <p>Evaluated in the same place, and for the same reason, as {@link IfMatch}: inside the write
 * transaction, where the store's single writer makes the comparison a compare-and-swap rather than a
 * guess about state that may already have moved (finding H23). The HTTP layer also checks it early
 * so a doomed request is refused before its body is read; that check decides nothing.
 *
 * <p>Kept apart from {@link IfMatch} rather than folded into it, because the two differ in exactly
 * the place a shared type would hide: an <em>absent</em> {@code If-Match} means "no precondition,
 * proceed", while an absent {@code If-None-Match} means the same thing for a write but the opposite
 * on a read (send the body). The tag syntax is shared, and is parsed by {@link IfMatch}, so the two
 * cannot drift about what a tag is.
 *
 * @author Erich Bremer
 */
public record IfNoneMatch(String header) {

    /** No precondition: the client sent no {@code If-None-Match}. */
    public static final IfNoneMatch NONE = new IfNoneMatch(null);

    public static IfNoneMatch of(String headerValue) {
        return headerValue == null ? NONE : new IfNoneMatch(headerValue.trim());
    }

    /** True if the client sent the header at all. */
    public boolean isPresent() {
        return header != null;
    }

    /**
     * True if the client sent {@code If-None-Match: *} — "only if it does not exist yet".
     *
     * <p>Distinguished from a tag list because this is the only form that relaxes the rule requiring
     * a replacement to name the version it replaces. A tag list must not: {@code If-None-Match:
     * "someone-else's-tag"} names no version of <em>this</em> resource, so honouring it as a
     * precondition would turn one junk header into an unconditional overwrite — the lost update
     * findings H23 and M20 exist to prevent.
     */
    public boolean isStar() {
        return "*".equals(header);
    }

    /**
     * True if this precondition permits a write against {@code existing} ({@code null} when the
     * resource does not exist).
     *
     * <p>RFC 9110 &sect;13.1.2: with no current representation the condition is true whatever was
     * sent — including {@code *}, whose whole purpose is that case. With one, the condition is false
     * if {@code *} was sent or if any listed tag names that representation.
     */
    public boolean satisfiedBy(LwsResource existing) {
        if (!isPresent() || existing == null) {
            return true;
        }
        if (isStar()) {
            return false;
        }
        return !IfMatch.of(header).namesState(existing.etag());
    }
}
