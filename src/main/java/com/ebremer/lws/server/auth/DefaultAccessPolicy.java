package com.ebremer.lws.server.auth;

import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.AccessPolicy;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.LwsResource;

/**
 * The default owner-based authorization policy.
 *
 * <ul>
 *   <li><b>Open mode</b> (no owners configured): everything is permitted — development only.</li>
 *   <li><b>Owners</b> (configured WebIDs, or a resource's recorded owner) get full control.</li>
 *   <li><b>Everyone else</b>: may read a resource only if it is marked publicly readable; no writes.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class DefaultAccessPolicy implements AccessPolicy {

    private final LwsConfiguration config;

    public DefaultAccessPolicy(LwsConfiguration config) {
        this.config = config;
    }

    @Override
    public boolean canRead(LwsPrincipal principal, LwsResource resource) {
        return config.isOpenMode() || isOwner(principal, resource) || resource.publicRead();
    }

    @Override
    public boolean canWrite(LwsPrincipal principal, LwsResource resource) {
        return config.isOpenMode() || isOwner(principal, resource);
    }

    @Override
    public boolean canControl(LwsPrincipal principal, LwsResource resource) {
        return config.isOpenMode() || isOwner(principal, resource);
    }

    private boolean isOwner(LwsPrincipal principal, LwsResource resource) {
        if (principal == null || principal.webId() == null) {
            return false;
        }
        if (config.ownerWebIds().contains(principal.webId())) {
            return true;
        }
        return resource.owner() != null && resource.owner().equals(principal.webId());
    }
}
