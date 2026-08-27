package com.ebremer.lws.server.auth;

import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.AccessPolicy;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.LwsResource;

/**
 * The default owner-based authorization policy.
 *
 * <ul>
 *   <li><b>Open mode</b> (no owners configured): reads and writes are permitted — development
 *       only, and behind {@code lws.dev.open}. It has no <em>controller</em>: with nobody
 *       configured there is nobody to have been entrusted with the storage.</li>
 *   <li><b>Owners</b> (configured WebIDs, or a resource's recorded owner) get full control.</li>
 *   <li><b>Everyone else</b>: may read only if the storage is configured public-read
 *       ({@code lws.public-read}, storage-wide); no writes. Per-resource access is an access grant
 *       or WAC.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class DefaultAccessPolicy implements AccessPolicy {

    private final LwsConfiguration config;

    public DefaultAccessPolicy(LwsConfiguration config) {
        this.config = config;
    }

    /**
     * Public readability is deliberately storage-wide, not per resource.
     *
     * <p>There used to be a {@code publicRead} boolean on each resource, which read as per-resource
     * state but could only ever hold {@code config.publicReadDefault()}: it was stamped at creation
     * and carried forward verbatim by every write path, and nothing — no header, no servlet, no UI
     * action — could change it. That made it two lies at once. It looked like a control an operator
     * had, and because it was stamped rather than consulted, resources created while
     * {@code lws.public-read=true} stayed world-readable after the operator set it to false.
     *
     * <p>It is not replaced with a real per-resource control, because two already exist and are
     * specified: an <em>access grant</em> with {@code assignee: foaf:Agent} opens one resource — or,
     * with a {@code target.value} ending in {@code /}, one subtree — to the world, issued only by a
     * storage controller and revocable on the next request; and WAC does per-agent access properly.
     * Do not reintroduce the boolean.
     */
    @Override
    public boolean canRead(LwsPrincipal principal, LwsResource resource) {
        return config.isOpenMode() || isOwner(principal, resource) || config.publicReadDefault();
    }

    @Override
    public boolean canWrite(LwsPrincipal principal, LwsResource resource) {
        return config.isOpenMode() || isOwner(principal, resource);
    }

    /**
     * Note the absent {@code isOpenMode()} disjunct, which {@link #canRead} and {@link #canWrite}
     * both keep.
     *
     * <p>Open mode means no authorization is configured. That is a reason to permit reads and writes
     * on a development box; it is not a reason to believe any particular agent was <em>entrusted</em>
     * with the storage. Control is the authority that grant issuance, ACL editing and subscription
     * management all borrow from, and borrowing it from an absence is how a self-signed
     * {@code did:key} issued itself a storage-wide access grant that outlived a restart, an owner
     * list, {@code lws.public-read=false} and a switch to WAC (H22).
     */
    @Override
    public boolean canControl(LwsPrincipal principal, LwsResource resource) {
        return isOwner(principal, resource);
    }

    /**
     * The three ways this policy says yes without consulting the resource at all: open mode, a WebID
     * in {@code lws.owners}, and (for reads) the storage-wide public-read flag.
     *
     * <p>Read straight off {@link #canRead}/{@link #canWrite}/{@link #canControl} above, with the
     * one disjunct that <em>does</em> depend on the resource — {@code resource.owner()} matching —
     * left out. That omission is what makes this safe: a resource-owner who is not a configured owner
     * gets {@code false} here and is authorized member by member, exactly as before.
     *
     * <p>What it buys is that a container listing under the ordinary deployment stops asking one
     * question per member. A 200,000-member listing was 200,000 authorization decisions, each of them
     * a registry lookup in a transaction of its own, to evaluate a predicate that could not have
     * varied (findings M23 and M39).
     */
    @Override
    public boolean permitsEveryResource(LwsPrincipal principal, AclMode mode) {
        boolean configuredOwner = principal != null && principal.webId() != null
                && config.ownerWebIds().contains(principal.webId());
        return switch (mode) {
            case READ -> config.isOpenMode() || configuredOwner || config.publicReadDefault();
            case WRITE, APPEND, DELETE -> config.isOpenMode() || configuredOwner;
            // Note the absent isOpenMode(), matching canControl: open mode means no authorization is
            // configured, which is not a reason to believe anyone was entrusted with the storage.
            case CONTROL -> configuredOwner;
        };
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
