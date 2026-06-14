package com.ebremer.lws.server.auth;

import com.ebremer.lws.server.core.AccessPolicy;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.Authorizer;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.LwsResource;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.rdf.RdfStore;

/**
 * {@link Authorizer} that adapts the simple owner/public-read {@link AccessPolicy} to the
 * mode-and-IRI interface. This is the default (single-tenant) authorizer; WAC is the multi-user
 * alternative.
 *
 * @author Erich Bremer
 */
public final class OwnerAuthorizer implements Authorizer {

    private final RdfStore rdf;
    private final ResourceRegistry registry;
    private final AccessPolicy policy;

    public OwnerAuthorizer(RdfStore rdf, ResourceRegistry registry, AccessPolicy policy) {
        this.rdf = rdf;
        this.registry = registry;
        this.policy = policy;
    }

    @Override
    public boolean allows(LwsPrincipal principal, String targetIri, AclMode mode) {
        LwsResource r = rdf.read(conn -> registry.find(conn, targetIri).orElse(null));
        if (r == null) {
            return false;
        }
        return switch (mode) {
            case READ -> policy.canRead(principal, r);
            case WRITE, APPEND -> policy.canWrite(principal, r);
            case CONTROL -> policy.canControl(principal, r);
        };
    }
}
