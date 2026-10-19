package com.ebremer.lws.server.core;

import java.util.Map;
import org.apache.jena.rdfconnection.RDFConnection;

/**
 * Store-local state belonging to a resource that must follow it when it moves to another container,
 * in the same unit of work as the move itself: the counterpart of {@link ResourceCleanup}.
 *
 * <p>This server derives a resource's IRI from its place in the containment hierarchy, so moving a
 * resource gives it, and every resource below it, a new IRI (lws10-core, Moving Resources, where the
 * storage describes {@code preservesIdentifier: false}). Whatever a component keeps keyed by those
 * IRIs — a linkset row, an ACL graph and its entity-tag — has to be re-keyed, or the moved resource
 * arrives without its metadata and its access control while the old IRI keeps both, to be inherited
 * by whatever is created there next (the H24 resurrection {@link ResourceCleanup} exists to prevent,
 * reached by a different road). The draft is explicit that "auxiliary resources whose lifetime is
 * bound to the moved resource remain bound to it after the move".
 *
 * <p>Like a cleanup, a relocation runs on the caller's connection before the move's transaction
 * commits, so a failure aborts the whole move: it is all or nothing, as the draft requires. And like
 * a cleanup it must not dereference anything remote, because it runs with the store's single writer
 * lock held (see {@code RdfStore#inUnitOfWork}).
 *
 * <p>Effects outside the store — notifications, the in-memory search index — are not relocations:
 * they follow from the {@link ActivityKind#MOVE} event once the move has committed.
 *
 * @author Erich Bremer
 */
@FunctionalInterface
public interface ResourceRelocation {

    /**
     * Re-key whatever this component stores for the moved resources, using the caller's connection.
     *
     * <p>Called once per move. {@code moved} maps every IRI that changed to its new value: the moved
     * resource first, then, for a container, each of its descendants. It is the whole mapping rather
     * than one pair because state belonging to one moved resource can name another (an ACL on a
     * moved container that names a group document stored inside it), and that reference has to
     * follow too.
     *
     * @param conn  the move's own connection, inside its write transaction
     * @param moved previous IRI to new IRI, for the moved resource and every descendant
     */
    void onMove(RDFConnection conn, Map<String, String> moved);
}
