package com.ebremer.lws.server.ui;

import org.apache.wicket.Session;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.request.Request;
import org.apache.wicket.request.Response;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.LwsCredentialValidator;
import com.ebremer.lws.server.auth.WacAclService;
import com.ebremer.lws.server.core.ResourceService;

/**
 * The Apache Wicket application powering the storage management UI. Dependencies are supplied by
 * constructor (no Spring/Wicket-Spring coupling), so the same application runs under bare Jetty.
 *
 * @author Erich Bremer
 */
public final class LwsWebApplication extends WebApplication {

    private final transient ResourceService resources;
    private final transient LwsConfiguration config;
    private final transient WacAclService aclService;     // nullable: only in WAC mode
    private final transient LwsCredentialValidator validator; // for token sign-in

    public LwsWebApplication(ResourceService resources, LwsConfiguration config,
            WacAclService aclService, LwsCredentialValidator validator) {
        this.resources = resources;
        this.config = config;
        this.aclService = aclService;
        this.validator = validator;
    }

    public static LwsWebApplication instance() {
        return (LwsWebApplication) get();
    }

    public ResourceService resources() {
        return resources;
    }

    public LwsConfiguration config() {
        return config;
    }

    /** The WAC ACL service, or {@code null} when access control is owner-based. */
    public WacAclService aclService() {
        return aclService;
    }

    public LwsCredentialValidator validator() {
        return validator;
    }

    public boolean wacEnabled() {
        return aclService != null;
    }

    @Override
    public Class<? extends WebPage> getHomePage() {
        return BrowsePage.class;
    }

    @Override
    public Session newSession(Request request, Response response) {
        return new LwsSession(request);
    }

    @Override
    protected void init() {
        super.init();
        // Inline styles keep the UI dependency-free; relax CSP so they render.
        getCspSettings().blocking().disabled();
        mountPage("/browse", BrowsePage.class);
        mountPage("/login", LoginPage.class);
        mountPage("/oidc-login", OidcLoginPage.class);
    }
}
