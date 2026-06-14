package com.ebremer.lws.server.core;

/**
 * An authenticated agent, as established by an LWS authentication suite (e.g. OpenID Connect).
 *
 * @param webId    the agent's subject identifier / controlled-identifier IRI (the OIDC {@code sub})
 * @param issuer   the identity provider that vouched for the agent (the OIDC {@code iss})
 * @param clientId the client application the credential was issued to (the OIDC {@code azp}), may be null
 *
 * @author Erich Bremer
 */
public record LwsPrincipal(String webId, String issuer, String clientId) implements java.io.Serializable {

    /** A {@code null} principal represents an unauthenticated (anonymous) agent. */
    public static boolean isAnonymous(LwsPrincipal principal) {
        return principal == null;
    }
}
