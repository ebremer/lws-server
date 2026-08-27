package com.ebremer.lws.server.ui;

import java.util.Optional;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.wicket.protocol.http.servlet.ServletWebRequest;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.jee.context.JEEContextFactory;
import org.pac4j.jee.context.JEEFrameworkParameters;
import org.pac4j.jee.context.session.JEESessionStore;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Completes the interactive OpenID Connect browser login. The pac4j {@code SecurityFilter}
 * protects the path that maps to this page, so by the time it renders, pac4j has authenticated the
 * user and stored a profile in the HTTP session; this page reads that profile and adopts it into
 * the {@link LwsSession}, then redirects to the browser. Reached only when OIDC login is configured.
 *
 * @author Erich Bremer
 */
public final class OidcLoginPage extends BasePage {

    public OidcLoginPage() {
        if (!app().config().oidcLoginEnabled()) {
            getSession().error("OpenID Connect login is not configured.");
            setResponsePage(LoginPage.class);
            return;
        }
        HttpServletRequest request = ((ServletWebRequest) getRequest()).getContainerRequest();
        // getContainerResponse() unwraps whichever WebResponse wrapper is active (in the live
        // container the response is a HeaderBufferingWebResponse, not a ServletWebResponse).
        HttpServletResponse response = (HttpServletResponse) getResponse().getContainerResponse();
        WebContext context = JEEContextFactory.INSTANCE.newContext(new JEEFrameworkParameters(request, response));
        ProfileManager profileManager = new ProfileManager(context, new JEESessionStore());

        Optional<UserProfile> profile = profileManager.getProfile();
        if (profile.isEmpty()) {
            getSession().error("OpenID Connect sign-in did not complete.");
            setResponsePage(LoginPage.class);
            return;
        }
        UserProfile up = profile.get();
        Object issuer = up.getAttribute("iss");
        String iss = issuer == null ? null : issuer.toString();
        // pac4j has verified the ID token's signature, issuer, expiry, nonce and audience — but not
        // that this subject claims this issuer, which is the LWS suite's actual trust step and what
        // the token form on the login page gets from app().validator(). Without it the console
        // would be a second OpenID door with a weaker guarantee than the API's, and the default one.
        if (!app().validator().openIdSubjectTrustsIssuer(up.getId(), iss)) {
            profileManager.removeProfiles();
            getSession().error("Signed in with " + (iss == null ? "the provider" : iss)
                    + ", but " + up.getId() + " does not name it as its OpenID provider.");
            setResponsePage(LoginPage.class);
            return;
        }
        LwsSession.get().signIn(new LwsPrincipal(up.getId(), iss, app().config().oidcClientId()));
        profileManager.removeProfiles(); // identity now lives in the Wicket session
        getSession().success("Signed in as " + up.getId());
        setResponsePage(BrowsePage.class);
    }
}
