package com.ebremer.lws.server.core;

/**
 * Authorization policy for LWS resources. The LWS core draft leaves the authorization model
 * unspecified, so this is an extension point: the default implementation is owner-based, but
 * any policy (WAC/ACP/ZCAP) can be supplied without touching the service layer.
 *
 * <p>A {@code null} principal is anonymous.
 *
 * @author Erich Bremer
 */
public interface AccessPolicy {

    boolean canRead(LwsPrincipal principal, LwsResource resource);

    boolean canWrite(LwsPrincipal principal, LwsResource resource);

    /** Whether the agent may control a resource (manage its ACL, create subscriptions over it). */
    boolean canControl(LwsPrincipal principal, LwsResource resource);

    /**
     * Whether this policy answers {@code true} for {@code mode} on every resource in the storage,
     * without needing to look at any of them.
     *
     * <p>Purely an optimization, and {@code false} is always safe — see
     * {@link Authorizer#allowsEverything}, which is what consumes it. The default is {@code false},
     * which is correct for any policy that reads the resource.
     */
    default boolean permitsEveryResource(LwsPrincipal principal, AclMode mode) {
        return false;
    }
}
