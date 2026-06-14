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
}
