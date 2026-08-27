package com.ebremer.lws.server.core;

import org.apache.jena.rdfconnection.RDFConnection;

/**
 * Store-local state belonging to a resource that must disappear <em>with</em> it, in the same unit
 * of work as the delete itself.
 *
 * <p>Deliberately distinct from {@link ResourceEventListener}, which is the fan-out for effects
 * <em>outside</em> the store — a notification, a search index — where a failure is logged and the
 * delete still stands. A cleanup runs on the caller's connection before the transaction commits, so
 * a failure aborts the whole delete instead of being swallowed.
 *
 * <p>That is finding H24. The ACL graph and the linkset row used to be erased by post-commit
 * listeners, each opening a transaction of its own and each catching its own exception, under an
 * {@code emit} that caught anything they missed. A cleanup that failed — store contention, or the
 * JVM killed between the commit and the cleanup — left a deleted resource's ACL behind, and a
 * resource later created at the same path inherited it: an own-ACL outranks container inheritance,
 * so whoever the old ACL named silently held access to a resource they had never been granted.
 *
 * <p>Implementations must not dereference anything remote. They run with the store's single writer
 * lock held; see {@code RdfStore#inUnitOfWork}.
 *
 * @author Erich Bremer
 */
@FunctionalInterface
public interface ResourceCleanup {

    /** Erase whatever this component stores for {@code iri}, using the caller's connection. */
    void onDelete(RDFConnection conn, String iri);
}
