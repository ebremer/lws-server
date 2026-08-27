package com.ebremer.lws.server.ui;

import java.util.Locale;
import org.apache.wicket.Application;
import org.apache.wicket.RuntimeConfigurationType;
import org.apache.wicket.Session;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.protocol.http.ResourceIsolationRequestCycleListener;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.request.Request;
import org.apache.wicket.request.Response;
import org.apache.wicket.settings.ExceptionSettings;
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

    /**
     * Run in {@code DEPLOYMENT} unless an operator explicitly asks for development.
     *
     * <p>Wicket's default when nothing is configured is {@code DEVELOPMENT}, and nothing here ever
     * overrode it — so the packaged jar shipped with {@code SHOW_EXCEPTION_PAGE}, a one-second
     * markup-polling thread for the life of the process, unstripped {@code wicket:} tags and the
     * Ajax debug window. Any unhandled exception rendered a full stack trace to whoever triggered
     * it, authenticated or not (finding M29).
     *
     * <p>{@code DEVELOPMENT} coming back from {@code super} is ambiguous — it means either "an
     * operator asked for it" or "nobody said anything at all" — so the operator's own words are
     * what distinguish them. Wicket's switch is left intact rather than replaced by a new
     * {@code lws.*} key: an operator debugging the console already knows that one, and a second
     * spelling for the same setting is a way for the two to disagree.
     */
    @Override
    public RuntimeConfigurationType getConfigurationType() {
        RuntimeConfigurationType configured = super.getConfigurationType();
        if (configured == RuntimeConfigurationType.DEVELOPMENT && !developmentRequested()) {
            return RuntimeConfigurationType.DEPLOYMENT;
        }
        return configured;
    }

    /** True only if development mode was asked for, in any of the three places Wicket looks. */
    private boolean developmentRequested() {
        return isDevelopment(initParameter(Application.CONFIGURATION))
                || isDevelopment(property("wicket." + Application.CONFIGURATION))
                || isDevelopment(environment("WICKET_" + Application.CONFIGURATION.toUpperCase(Locale.ROOT)));
    }

    private String initParameter(String name) {
        try {
            return getServletContext() == null ? null : getServletContext().getInitParameter(name);
        } catch (RuntimeException e) {
            return null; // no servlet context yet (or none at all, under WicketTester)
        }
    }

    private static String property(String name) {
        try {
            return System.getProperty(name);
        } catch (SecurityException e) {
            return null;
        }
    }

    private static String environment(String name) {
        try {
            return System.getenv(name);
        } catch (SecurityException e) {
            return null;
        }
    }

    private static boolean isDevelopment(String value) {
        return value != null
                && value.trim().equalsIgnoreCase(RuntimeConfigurationType.DEVELOPMENT.name());
    }

    @Override
    protected void init() {
        super.init();
        // Inline styles keep the UI dependency-free; relax CSP so they render.
        getCspSettings().blocking().disabled();
        // Wicket has no CSRF token, and its stateful callback URLs are guessable (a small
        // per-session page id). This listener is Wicket 10's CSRF defence — Fetch Metadata with an
        // Origin fallback — and is NOT installed by default, so a cross-site request could
        // otherwise invoke any component callback in a signed-in user's session. Every destructive
        // action in the console is also a POST rather than an <a href> GET.
        getRequestCycleListeners().add(new ResourceIsolationRequestCycleListener());
        // Belt and braces with getConfigurationType(): an operator who does turn development mode
        // back on for the markup polling should still not be publishing stack traces to visitors.
        getExceptionSettings().setUnexpectedExceptionDisplay(ExceptionSettings.SHOW_INTERNAL_ERROR_PAGE);
        mountPage("/browse", BrowsePage.class);
        mountPage("/login", LoginPage.class);
        mountPage("/oidc-login", OidcLoginPage.class);
    }
}
