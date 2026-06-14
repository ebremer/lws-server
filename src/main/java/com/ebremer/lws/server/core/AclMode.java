package com.ebremer.lws.server.core;

/**
 * The access modes an operation requires, aligned with WAC {@code acl:mode} values.
 *
 * @author Erich Bremer
 */
public enum AclMode {

    /** Read a resource (GET/HEAD; list a container). */
    READ,
    /** Modify or remove an existing resource (PUT-overwrite, PATCH, DELETE). */
    WRITE,
    /** Add new information to a container (POST, PUT of a new resource). Implied by WRITE. */
    APPEND,
    /** Read and write a resource's access control (its ACL resource). */
    CONTROL
}
