package com.ebremer.lws.server.auth;

import org.pac4j.core.config.Config;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Builds the pac4j {@link Config} for optional interactive OpenID Connect sign-in to the Wicket
 * UI (jakartaee-pac4j {@code SecurityFilter}/{@code CallbackFilter}). This is separate from
 * resource-server token validation ({@link LwsOpenIdValidator}); it is only wired when an OIDC
 * client is configured.
 *
 * @author Erich Bremer
 */
public final class Pac4jSupport {

    private Pac4jSupport() {
    }

    public static final String CLIENT_NAME = "OidcClient";
    public static final String CALLBACK_PATH = "/callback";
    /** UI path that triggers the OIDC redirect; also where the callback returns to. */
    public static final String LOGIN_PATH = "/app/oidc-login";

    /** Build the pac4j config, or {@code null} if UI login is not configured. */
    public static Config buildConfig(LwsConfiguration config) {
        if (!config.oidcLoginEnabled()) {
            return null;
        }
        OidcConfiguration oidc = new OidcConfiguration();
        oidc.setClientId(config.oidcClientId());
        oidc.setSecret(config.oidcClientSecret());
        oidc.setDiscoveryURI(config.oidcDiscoveryUri());
        oidc.setScope("openid profile");
        oidc.setUseNonce(true);
        // Pin secret-based client authentication: pac4j otherwise adopts the OP's first advertised
        // token_endpoint_auth_method, which for Keycloak is private_key_jwt (no such key is
        // configured here, so the client would fail with "privateKeyJwtConfig cannot be null").
        oidc.setClientAuthenticationMethodAsString("client_secret_basic");

        OidcClient client = new OidcClient(oidc);
        client.setName(CLIENT_NAME);

        return new Config(config.baseUri() + CALLBACK_PATH, client);
    }
}
