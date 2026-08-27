package com.ebremer.lws.server.core;

/**
 * The access modes an operation requires, aligned with WAC {@code acl:mode} values.
 *
 * @author Erich Bremer
 */
public enum AclMode {

    /** Read a resource (GET/HEAD; list a container). */
    READ,
    /** Modify an existing resource in place (PUT-overwrite, PATCH, a metadata write). */
    WRITE,
    /** Add new information to a container (POST, PUT of a new resource). Implied by WRITE. */
    APPEND,
    /**
     * Remove a resource (DELETE), including every member of a subtree under
     * {@code Depth: infinity}.
     *
     * <p>Separate from {@link #WRITE} because the ODRL vocabulary access grants are written in
     * distinguishes {@code modify} from {@code delete}, and collapsing the two onto one mode made
     * each imply the other: a grant saying only {@code "action":["modify"]} authorized
     * {@code DELETE /alice/} with {@code Depth: infinity}, and one saying only {@code ["delete"]}
     * authorized rewriting the content (finding M8).
     *
     * <p>Web Access Control has no separate delete permission — {@code acl:Write} covers removal —
     * so under WAC this maps to {@code acl:Write}, exactly as {@link #WRITE} does. The distinction
     * is therefore visible only where the underlying model draws it, which is grants. Owner-based
     * authorization likewise treats the two alike: an owner may do both, and a non-owner neither.
     */
    DELETE,
    /** Read and write a resource's access control (its ACL resource). */
    CONTROL
}
