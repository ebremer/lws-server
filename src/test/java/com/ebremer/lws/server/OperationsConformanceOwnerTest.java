package com.ebremer.lws.server;

import java.util.Properties;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * The lws10-core operations conformance suite run in the posture an operator actually deploys: a
 * configured storage owner ({@code lws.owners}), {@code lws.dev.open} unset, and every request
 * carrying that owner's credential.
 *
 * <p><strong>What this pins (finding M47).</strong> The suite in
 * {@link AbstractOperationsConformance} used to exist only in open mode, where
 * {@code DefaultAccessPolicy.canRead} and {@code canWrite} return true before looking at anything —
 * so four hundred lines of protocol conformance were evidence about a posture nobody runs, and said
 * nothing about the one everybody does. Authorization sits in front of every operation those tests
 * exercise, and it can change what a client observes without any protocol code changing: a
 * conditional PUT answered {@code 403} where the spec requires {@code 412}, an {@code Allow} header
 * trimmed to what the principal may do, a container listing filtered member by member, an absent
 * resource masked as {@code 401} instead of {@code 404}. This class is the second data point that
 * turns "the protocol works" into "the protocol works when it is guarded".
 *
 * <p><strong>Why the expected status codes are identical.</strong> The subclasses share every
 * assertion deliberately — a divergence would be the finding, not a maintenance problem.
 * {@code ResourceService.read} resolves existence before authorizing, so a missing resource is
 * {@code 404} in both runs; and where existence is <em>not</em> resolvable, {@code absent(...)}
 * answers {@code 404} whenever {@code authorizer.allowsEverything(principal, READ)} holds, which it
 * does for a WebID listed in {@code lws.owners}. The one operation whose outcome genuinely differs
 * between the two postures is {@code CONTROL} — {@code DefaultAccessPolicy.canControl} has no
 * {@code isOpenMode()} disjunct, on purpose — and the conformance suite touches no ACL, no access
 * grant and no subscription, so it never asks a control question.
 *
 * @author Erich Bremer
 */
class OperationsConformanceOwnerTest extends AbstractOperationsConformance {

    /** The owner's Bearer credential, minted in {@link #configure(Properties)}. */
    private String token;

    /**
     * The credential is minted for <em>this</em> storage: {@code lws.audience.require} defaults to
     * true and the accepted audiences default to the base URI, so a token with no {@code aud} — or
     * one naming another storage — is refused. That is why the hook is handed the {@link Properties}
     * the base class has already populated rather than nothing: the base URI carries the port, which
     * is only known once the server has claimed one.
     */
    @Override
    protected void configure(Properties p) {
        DidKeyTool.Minted owner = DidKeyTool.mint(null, 3600, p.getProperty("lws.base-uri"));
        token = owner.token();
        p.setProperty("lws.owners", owner.did());
    }

    @Override
    protected String authorizationToken() {
        return token;
    }
}
