package com.ebremer.lws.server.auth;

import java.util.List;
import java.util.Set;
import com.nimbusds.jwt.JWTClaimsSet;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Decides whether a presented JWT credential was minted <em>for this storage</em>, by checking its
 * {@code aud} claim against a configured set of accepted audience values.
 *
 * <p>Without this check a signed token is accepted by every LWS storage that trusts the same
 * issuer (or, for the self-signed suites, by every storage at all): a token a user presents to
 * storage A can be replayed verbatim against storage B, and an ID token minted for any other
 * relying party of the same OpenID provider authenticates here as that user. Binding the credential
 * to an audience is what makes a leaked or harvested token useless elsewhere.
 *
 * <p>Semantics:
 * <ul>
 *   <li>a token whose {@code aud} contains any accepted value is admitted;</li>
 *   <li>a token whose {@code aud} is present but matches nothing is <strong>always</strong>
 *       rejected — a credential addressed to someone else is never accepted here, regardless of
 *       configuration;</li>
 *   <li>a token with no {@code aud} at all is rejected when {@code lws.audience.require} is set
 *       (the default), and admitted otherwise for interoperability with clients that omit it.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class AudiencePolicy {

    private final Set<String> accepted;
    private final boolean require;

    public AudiencePolicy(Set<String> accepted, boolean require) {
        this.accepted = Set.copyOf(accepted);
        this.require = require;
    }

    /** No audience restriction at all. For tests and for suites where the check does not apply. */
    public static AudiencePolicy permitAll() {
        return new AudiencePolicy(Set.of(), false);
    }

    /** The policy configured by {@code lws.audience} / {@code lws.audience.require}. */
    public static AudiencePolicy from(LwsConfiguration config) {
        return new AudiencePolicy(config.acceptedAudiences(), config.audienceRequired());
    }

    /** True if {@code claims} carries an audience this storage accepts (see the class javadoc). */
    public boolean permits(JWTClaimsSet claims) {
        if (accepted.isEmpty()) {
            return true; // no audience configured: the policy is disabled
        }
        List<String> audiences = claims.getAudience();
        if (audiences == null || audiences.isEmpty()) {
            return !require;
        }
        for (String audience : audiences) {
            if (accepted.contains(audience)) {
                return true;
            }
        }
        return false;
    }

    /** The audience values this storage accepts; empty when the policy is disabled. */
    public Set<String> accepted() {
        return accepted;
    }

    /** Whether a credential must carry an {@code aud} claim at all. */
    public boolean required() {
        return require;
    }
}
