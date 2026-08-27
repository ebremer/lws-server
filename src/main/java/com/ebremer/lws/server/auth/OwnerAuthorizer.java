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

    /**
     * Owner-based authorization is uniform for a configured owner, in open mode, and for reads on a
     * public-read storage, so a caller with many resources to authorize can skip the loop
     * (findings M23/M39). The one per-resource disjunct — a resource's own recorded owner — is
     * deliberately not counted; see {@code DefaultAccessPolicy.permitsEveryResource}.
     */
    @Override
    public boolean allowsEverything(LwsPrincipal principal, AclMode mode) {
        return policy.permitsEveryResource(principal, mode);
    }

    @Override
    public boolean allows(LwsPrincipal principal, String targetIri, AclMode mode) {
        LwsResource r = rdf.read(conn -> registry.find(conn, targetIri).orElse(null));
        if (r == null) {
            return false;
        }
        return switch (mode) {
            case READ -> policy.canRead(principal, r);
            // DELETE alongside WRITE: the owner model has no per-action vocabulary — an owner may
            // do both and a non-owner neither — so the distinction access grants draw between
            // "modify" and "delete" (finding M8) simply does not arise here.
            case WRITE, APPEND, DELETE -> policy.canWrite(principal, r);
            case CONTROL -> policy.canControl(principal, r);
        };
    }
}
