package com.ebremer.lws.server.core;

import java.util.Set;

/**
 * Per-request context for authorization, carried in thread-locals so it reaches the
 * {@link Authorizer} (and access-grant evaluation) without widening their interfaces. It holds:
 * <ul>
 *   <li>the request's {@code Origin} — for Web Access Control {@code acl:origin} (app-scoped access);</li>
 *   <li>the purposes the client declares for the request (the {@code LWS-Purpose} header) — for ODRL
 *       {@code purpose} constraints on access grants.</li>
 * </ul>
 *
 * <p>Both are client-asserted (declared, not cryptographically attested), as is the nature of
 * origin/purpose policy. The HTTP layer sets this at the start of every request and clears it when
 * the request completes.
 *
 * @author Erich Bremer
 */
public final class RequestContext {

    private static final ThreadLocal<String> ORIGIN = new ThreadLocal<>();
    private static final ThreadLocal<Set<String>> PURPOSES = new ThreadLocal<>();

    private RequestContext() {
    }

    /** Set the request Origin (or clear it when {@code origin} is null/blank). */
    public static void setOrigin(String origin) {
        if (origin == null || origin.isBlank()) {
            ORIGIN.remove();
        } else {
            ORIGIN.set(origin.trim());
        }
    }

    /** The current request's {@code Origin}, or {@code null} if none was sent. */
    public static String origin() {
        return ORIGIN.get();
    }

    /** Set the purposes the client declares for this request (or clear when empty). */
    public static void setPurposes(Set<String> purposes) {
        if (purposes == null || purposes.isEmpty()) {
            PURPOSES.remove();
        } else {
            PURPOSES.set(Set.copyOf(purposes));
        }
    }

    /** The purposes declared for the current request (never null). */
    public static Set<String> purposes() {
        Set<String> purposes = PURPOSES.get();
        return purposes == null ? Set.of() : purposes;
    }

    /** Clear all request-scoped state (call in a finally at the end of request handling). */
    public static void clear() {
        ORIGIN.remove();
        PURPOSES.remove();
    }
}
