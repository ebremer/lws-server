package com.ebremer.lws.server.auth;

import java.time.Clock;
import com.ebremer.lws.server.core.AccessService;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.Authorizer;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * An {@link Authorizer} that augments a base authorizer with LWS <em>access grants</em>: an
 * operation is permitted if the base authorizer permits it <em>or</em> an active grant authorizes
 * it (see {@link AccessService#grants}). This makes grants effective regardless of the underlying
 * authorization model (owner-based or WAC) without mutating ACLs — revoking a grant (deleting the
 * record) immediately withdraws the access. Grants never confer {@code Control}.
 *
 * @author Erich Bremer
 */
public final class GrantAuthorizer implements Authorizer {

    private final Authorizer base;
    private final AccessService access;
    private final Clock clock;

    public GrantAuthorizer(Authorizer base, AccessService access, Clock clock) {
        this.base = base;
        this.access = access;
        this.clock = clock;
    }

    @Override
    public boolean allows(LwsPrincipal principal, String targetIri, AclMode mode) {
        return base.allows(principal, targetIri, mode)
                || access.grants(principal, targetIri, mode, clock.instant());
    }
}
