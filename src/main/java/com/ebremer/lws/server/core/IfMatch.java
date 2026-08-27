package com.ebremer.lws.server.core;

/**
 * A client's {@code If-Match} precondition, carried from the HTTP layer into the write transaction
 * that has to honour it.
 *
 * <p>It exists so that one comparison can be made in two places without the two drifting. The HTTP
 * layer evaluates it early, before it reads a request body it may be about to reject; that check is
 * advisory. {@link ResourceService} and {@link LinksetService} evaluate it again <em>inside</em> the
 * write transaction, and that one is authoritative — only there is it a compare-and-swap. The store
 * admits a single writer, so a tag compared under that writer's lock cannot go stale between the
 * comparison and the write it guards. Compared in a transaction of its own, as it used to be, it
 * proves nothing: every writer holding the same tag passes, every writer commits, and each silently
 * discards the one before it while answering {@code 204} (finding H23, and M18 for linksets).
 *
 * @author Erich Bremer
 */
public record IfMatch(String header) {

    /** No precondition: the client sent no {@code If-Match}. */
    public static final IfMatch NONE = new IfMatch(null);

    /**
     * Wrap a raw {@code If-Match} header value. Only an <em>absent</em> header is {@link #NONE}.
     *
     * <p>A header that is present but empty is malformed — RFC 9110 &sect;13.1.1 admits {@code *} or
     * a non-empty list of entity-tags and nothing else — and it stays present here, matching no tag,
     * so it is refused with {@code 412}. Folding it into {@link #NONE} instead would answer a
     * malformed precondition with an <em>unconditional</em> write, which is the one outcome a client
     * that bothered to send the header cannot have meant.
     */
    public static IfMatch of(String headerValue) {
        return headerValue == null ? NONE : new IfMatch(headerValue.trim());
    }

    /** True if the client named a version at all. */
    public boolean isPresent() {
        return header != null;
    }

    /**
     * True if this precondition is satisfied by {@code existing}, which is {@code null} when the
     * resource does not exist.
     *
     * <p>A precondition against a resource that does not exist is never satisfied — including
     * {@code If-Match: *}, whose meaning is "the resource must have a current representation"
     * (RFC 9110 &sect;13.1.1). A PUT carrying a tag asks to replace one specific version, so letting
     * it create instead would be the very lost update the header was sent to prevent: the version
     * the client meant to replace was deleted in the window, and the client would never learn that
     * its replacement was a resurrection.
     */
    public boolean satisfiedBy(LwsResource existing) {
        return existing == null ? !isPresent() : namesState(existing.etag());
    }

    /**
     * True if this precondition is satisfied by the entity-tag of a resource already known to
     * exist. {@code *} matches any such resource, including one carrying no tag of its own.
     *
     * <p>Both the bare and the quoted form of a tag are accepted, and a {@code W/} prefix is
     * stripped rather than rejected. That is weak comparison where RFC 9110 &sect;13.1.1 specifies
     * strong; it is the behaviour this server has always had, it is only ever reached by a client
     * that invents a weak form of a tag this server never emits, and tightening it is a protocol
     * change that belongs with the rest of the conditional-request tail rather than here.
     */
    public boolean matches(String currentEtag) {
        if (!isPresent()) {
            return true;
        }
        if (header.equals("*")) {
            return true;
        }
        if (currentEtag == null) {
            return false;
        }
        for (String token : tags()) {
            if (token.equals(currentEtag)) {
                return true;
            }
        }
        return false;
    }

    /**
     * True if this precondition names the <em>state</em> {@code currentEtag} identifies, whichever
     * representation the client happened to read it from.
     *
     * <p>A read hands out a tag qualified by the serialization it produced — {@code abc123.ttl} for
     * Turtle, {@code abc123.jsonld} for JSON-LD (RFC 9110 &sect;8.8.1, finding M21) — while a write
     * is conditioned on the resource's state, which is the {@code abc123} the registry stores and
     * which the write path compares against. Without this, a client that read Turtle and wrote back
     * the tag it was given would be refused {@code 412} for a version that had not changed.
     *
     * <p>The trailing token is stripped only when it is one this server mints
     * ({@code RdfFormats.isVariantToken}), so a client-invented tag containing a {@code .} cannot be
     * trimmed into matching. Used for {@code If-Match} on writes; {@link #matches} stays exact, which
     * is what keeps a cached Turtle representation from being revalidated against the JSON-LD one.
     */
    public boolean namesState(String currentStateEtag) {
        if (!isPresent()) {
            return true;
        }
        if (header.equals("*")) {
            return true;
        }
        if (currentStateEtag == null) {
            return false;
        }
        String state = Etags.baseOf(currentStateEtag);
        for (String token : tags()) {
            if (token.equals(currentStateEtag) || Etags.baseOf(token).equals(state)) {
                return true;
            }
        }
        return false;
    }

    /** The entity-tags named by the header, unquoted and with any {@code W/} prefix removed. */
    private java.util.List<String> tags() {
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String token : header.split(",")) {
            String t = token.trim();
            if (t.startsWith("W/")) {
                t = t.substring(2).trim();
            }
            if (t.length() >= 2 && t.startsWith("\"") && t.endsWith("\"")) {
                t = t.substring(1, t.length() - 1);
            }
            out.add(t);
        }
        return out;
    }
}
