package com.ebremer.lws.server.auth;

import java.time.Clock;
import com.ebremer.lws.server.LwsConfiguration;
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
    private final LwsConfiguration config;
    private final Clock clock;

    public GrantAuthorizer(Authorizer base, AccessService access, LwsConfiguration config, Clock clock) {
        this.base = base;
        this.access = access;
        this.config = config;
        this.clock = clock;
    }

    @Override
    public boolean allows(LwsPrincipal principal, String targetIri, AclMode mode) {
        return base.allows(principal, targetIri, mode)
                || access.grants(principal, targetIri, mode, clock.instant());
    }

    /**
     * A grant only ever adds access, so if the base authorizer already permits everything then so
     * does this. The converse is not asked: a set of grants that happens to cover every resource is
     * not something worth proving, and getting it wrong would disclose one.
     */
    @Override
    public boolean allowsEverything(LwsPrincipal principal, AclMode mode) {
        return base.allowsEverything(principal, mode);
    }

    /**
     * Warms the requester's own decision, and then each grant issuer's claim to still control the
     * storage.
     *
     * <p>Grant evaluation used to need no warm-up, because it read only local state. It now re-checks
     * every grant against its issuer, and that check runs inside the caller's transaction — where an
     * ACL conferring Control through an {@code acl:agentGroup} would find the group document
     * unreachable and fail closed (H16), silently voiding every grant that issuer ever made. Warming
     * the issuers here is what keeps that from happening.
     *
     * <p>{@code CONTROL} returns early because grants never confer it, so no issuer is consulted.
     */
    @Override
    public void prepare(LwsPrincipal principal, String targetIri, AclMode mode) {
        base.prepare(principal, targetIri, mode);
        if (mode == AclMode.CONTROL) {
            return;
        }
        for (String issuer : access.grantIssuers()) {
            base.prepare(new LwsPrincipal(issuer, null, null), config.storageRootIri(), AclMode.CONTROL);
        }
    }
}
