package com.ebremer.lws.server.core;

/**
 * Hierarchy-aware authorization decision point. Unlike {@link AccessPolicy} (which decides from a
 * single resource's metadata), an {@code Authorizer} is given the target IRI and the required
 * {@link AclMode}, so it can consult access-control resources and walk the containment hierarchy
 * (as Web Access Control requires).
 *
 * <p>A {@code null} principal is anonymous.
 *
 * @author Erich Bremer
 */
public interface Authorizer {

    boolean allows(LwsPrincipal principal, String targetIri, AclMode mode);

    /**
     * Whether this authorizer permits {@code mode} on <em>every</em> resource in the storage for this
     * principal, whatever any individual resource says.
     *
     * <p>An optimization and nothing else: {@code false} is always a safe answer, and the default.
     * Callers that would otherwise ask {@link #allows} once per member of a large set may skip the
     * loop entirely when this is {@code true}.
     *
     * <p>It exists because the answer is genuinely uniform in the ordinary deployment and genuinely
     * per-resource in the other one. Owner-based authorization decides from the configured owner
     * list, open mode and the storage-wide public-read flag — none of which vary by resource for a
     * configured owner — so a container listing that authorizes 200,000 members is asking one
     * question 200,000 times. Web Access Control decides from each resource's own ACL, so it answers
     * {@code false} and pays the loop, which is what per-resource access control costs.
     *
     * <p>An implementation must be certain. Answering {@code true} where {@link #allows} would have
     * said no discloses a resource; there is no case where returning {@code false} is wrong.
     */
    default boolean allowsEverything(LwsPrincipal principal, AclMode mode) {
        return false;
    }

    /**
     * Resolve, ahead of the decision, whatever an {@link #allows} call for the same arguments would
     * otherwise have to fetch over the network, so that the decision itself can be made from local
     * state alone.
     *
     * <p><b>Callers must invoke this outside any store transaction</b>, immediately before opening
     * the one whose callback will call {@code allows}. The metadata store admits a single writer, so
     * an authorizer that dereferences a remote document — Web Access Control resolves
     * {@code acl:agentGroup} membership by dereferencing the group document, at an address the
     * requester's own ACL chooses — would otherwise hold that writer lock for as long as the remote
     * host cares to take, stalling every other write in the storage.
     *
     * <p>This is a cache warm-up and nothing more. It is advisory: it never throws, never denies,
     * never changes a decision and never changes a status code. The decision stays where it is,
     * inside the transaction, evaluated against live state — which is what keeps a revocation that
     * commits in the meantime effective.
     *
     * <p>The default does nothing, which is correct for any authorizer that reads only local state.
     */
    default void prepare(LwsPrincipal principal, String targetIri, AclMode mode) {
    }
}
