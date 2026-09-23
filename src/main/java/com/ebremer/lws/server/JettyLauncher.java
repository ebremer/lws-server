package com.ebremer.lws.server;

import java.security.KeyStore;
import java.time.Duration;
import java.util.EnumSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import jakarta.servlet.DispatcherType;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.http.HttpCookie;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.ForwardedRequestCustomizer;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.apache.wicket.protocol.http.WicketFilter;
import org.pac4j.jee.filter.CallbackFilter;
import org.pac4j.jee.filter.SecurityFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.auth.Pac4jSupport;
import com.ebremer.lws.server.http.AccessServlet;
import com.ebremer.lws.server.http.BasePathRedirectFilter;
import com.ebremer.lws.server.http.CorsFilter;
import com.ebremer.lws.server.http.JwksServlet;
import com.ebremer.lws.server.http.LwsResourceServlet;
import com.ebremer.lws.server.http.SearchIndexServlet;
import com.ebremer.lws.server.http.StorageDescriptionServlet;
import com.ebremer.lws.server.http.SubscriptionServlet;
import com.ebremer.lws.server.oauth.AuthorizationServerMetadataServlet;
import com.ebremer.lws.server.oauth.TokenEndpointServlet;
import com.ebremer.lws.server.tls.AcmeCertificateManager;
import com.ebremer.lws.server.tls.AcmeChallengeServlet;
import com.ebremer.lws.server.tls.AcmeChallengeStore;
import com.ebremer.lws.server.tls.HstsFilter;
import com.ebremer.lws.server.tls.HttpsRedirectFilter;
import com.ebremer.lws.server.ui.LwsWebApplication;

/**
 * A bare Eclipse Jetty bootstrap with <em>no Spring at all</em>, demonstrating the intended
 * future deployment. It registers exactly the same {@link LwsComponents}-built servlets and
 * filters as {@link LwsServletConfig}; the two are line-for-line analogues, which is the whole
 * point of keeping the Spring footprint to a single configuration class.
 *
 * <p>Run with {@code java -cp ... com.ebremer.lws.server.JettyLauncher}.
 *
 * @author Erich Bremer
 */
public final class JettyLauncher {

    private static final Logger log = LoggerFactory.getLogger(JettyLauncher.class);

    private JettyLauncher() {
    }

    public static void main(String[] args) throws Exception {
        LwsConfiguration config;
        try {
            config = LwsConfiguration.load();
        } catch (LwsConfigurationException e) {
            log.error("Configuration error: {}", e.getMessage());
            System.exit(2);
            return; // unreachable after exit; satisfies definite assignment of config
        }
        LwsComponents c = LwsComponents.create(config);
        AcmeChallengeStore challenges = new AcmeChallengeStore();
        // Flipped by enableTls once the HTTPS connector is accepting connections. Until then the
        // redirect filter answers 503 rather than a cacheable redirect to a port nothing is bound
        // to (finding M28).
        java.util.concurrent.atomic.AtomicBoolean httpsReady = new java.util.concurrent.atomic.AtomicBoolean();

        Server server = new Server();
        server.addConnector(httpConnector(server, config));
        server.setHandler(buildHandler(c, config, challenges, httpsReady::get));

        ScheduledExecutorService renewals = config.tlsEnabled()
                ? Executors.newSingleThreadScheduledExecutor(daemon("lws-tls-renew")) : null;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                server.stop();
            } catch (Exception e) {
                log.warn("Error stopping Jetty: {}", e.toString());
            } finally {
                if (renewals != null) {
                    renewals.shutdownNow();
                }
                c.close();
            }
        }));
        server.start();
        if (config.tlsEnabled()) {
            enableTlsWithRetries(server, config, challenges, renewals, httpsReady);
        }
        log.info("LWS server (bare Jetty) listening on {}", config.baseUri());
        server.join();
    }

    /** First retry delay after a failed certificate acquisition; doubles up to {@link #TLS_RETRY_MAX}. */
    private static final Duration TLS_RETRY_INITIAL = Duration.ofSeconds(30);
    private static final Duration TLS_RETRY_MAX = Duration.ofMinutes(10);

    /**
     * Bring TLS up, and keep trying if it does not come up first time.
     *
     * <p>{@code enableTls} was {@code throws Exception} and uncaught in {@code main}, so a CA that
     * was rate-limiting, a DNS record that had not propagated, or a momentarily unreachable ACME
     * directory killed the whole process from an already-started server — while the renewal path
     * next to it had always caught its own failures and waited for the next tick. A first
     * acquisition is more likely to fail than a renewal, not less: it is the one that runs before
     * anybody has confirmed the domain resolves here.
     *
     * <p>Retried with exponential backoff and no attempt limit. The alternative to retrying forever
     * is giving up, and a server that has given up on TLS serves {@code 503} from
     * {@link HttpsRedirectFilter} with nothing scheduled to change that.
     */
    private static void enableTlsWithRetries(Server server, LwsConfiguration config,
            AcmeChallengeStore challenges, ScheduledExecutorService renewals,
            java.util.concurrent.atomic.AtomicBoolean httpsReady) {
        attemptTls(server, config, challenges, renewals, httpsReady, TLS_RETRY_INITIAL);
    }

    private static void attemptTls(Server server, LwsConfiguration config, AcmeChallengeStore challenges,
            ScheduledExecutorService renewals, java.util.concurrent.atomic.AtomicBoolean httpsReady,
            Duration backoff) {
        try {
            enableTls(server, config, challenges, renewals, httpsReady);
        } catch (Exception e) {
            log.error("Could not enable TLS ({}). Plaintext requests are answered 503 until it "
                    + "succeeds; retrying in {}s. Set lws.tls.enabled=false to serve plaintext instead.",
                    e.toString(), backoff.toSeconds());
            Duration next = backoff.multipliedBy(2).compareTo(TLS_RETRY_MAX) > 0 ? TLS_RETRY_MAX
                    : backoff.multipliedBy(2);
            renewals.schedule(() -> attemptTls(server, config, challenges, renewals, httpsReady, next),
                    backoff.toSeconds(), TimeUnit.SECONDS);
        }
    }

    /**
     * With the HTTP connector already up (so the ACME server can reach the HTTP-01 challenge),
     * obtain a certificate, start the HTTPS connector from it, and schedule periodic renewal with a
     * live reload of the {@code SslContextFactory}.
     */
    private static void enableTls(Server server, LwsConfiguration config, AcmeChallengeStore challenges,
            ScheduledExecutorService renewals, java.util.concurrent.atomic.AtomicBoolean httpsReady)
            throws Exception {
        AcmeCertificateManager acme = new AcmeCertificateManager(config, challenges);
        SslContextFactory.Server ssl = newSslContextFactory(acme.obtainKeyStore(), acme.keystorePassword());
        ServerConnector https = httpsConnector(server, config, ssl);
        server.addConnector(https);
        try {
            https.start(); // the server is already running, so the new connector is started explicitly
        } catch (Exception e) {
            // A connector that failed to start is still attached to the server; leaving it there
            // means the next attempt adds a second one bound to the same port.
            server.removeConnector(https);
            throw e;
        }
        httpsReady.set(true); // only now does a redirect have somewhere to point
        log.info("TLS enabled: HTTPS on :{} for {} (HTTP-01 challenge + redirect on :{})",
                config.tlsPort(), config.acmeDomains(), config.tlsHttpPort());
        renewals.scheduleAtFixedRate(() -> renewIfDue(acme, ssl), 12, 12, TimeUnit.HOURS);
    }

    private static void renewIfDue(AcmeCertificateManager acme, SslContextFactory.Server ssl) {
        try {
            if (!acme.dueForRenewal()) {
                return;
            }
            KeyStore keyStore = acme.obtainKeyStore();
            ssl.reload(factory -> {
                factory.setKeyStore(keyStore);
                factory.setKeyStorePassword(new String(acme.keystorePassword()));
            });
            log.info("Renewed and hot-reloaded the TLS certificate");
        } catch (Exception e) {
            log.warn("TLS certificate renewal failed (will retry on the next tick): {}", e.toString());
        }
    }

    private static SslContextFactory.Server newSslContextFactory(KeyStore keyStore, char[] password) {
        SslContextFactory.Server ssl = new SslContextFactory.Server();
        ssl.setKeyStore(keyStore);
        ssl.setKeyStorePassword(new String(password));
        return ssl;
    }

    private static ServerConnector httpsConnector(Server server, LwsConfiguration config,
            SslContextFactory.Server ssl) {
        HttpConfiguration httpsConfig = new HttpConfiguration();
        hideServerVersion(httpsConfig);
        httpsConfig.addCustomizer(new SecureRequestCustomizer());
        if (config.behindProxy()) {
            httpsConfig.addCustomizer(new ForwardedRequestCustomizer());
        }
        ServerConnector connector = new ServerConnector(server,
                new SslConnectionFactory(ssl, "http/1.1"), new HttpConnectionFactory(httpsConfig));
        connector.setPort(config.tlsPort());
        return connector;
    }

    /**
     * Stop advertising the exact Jetty version in {@code Server:} and in error pages.
     *
     * <p>It is not a vulnerability on its own, and it is not a control either — it is a free hint
     * that tells anyone scanning which advisories to try first. The Spring bootstrap already
     * suppressed it, so this connector was the only place the two deployments disagreed, and
     * "which of our two launchers is it" is itself something worth not saying.
     */
    private static void hideServerVersion(HttpConfiguration httpConfig) {
        httpConfig.setSendServerVersion(false);
        httpConfig.setSendXPoweredBy(false);
    }

    private static ThreadFactory daemon(String name) {
        return r -> {
            Thread t = new Thread(r, name);
            t.setDaemon(true);
            return t;
        };
    }

    /**
     * Build the HTTP connector. When {@code lws.behind-proxy} is set, a {@link ForwardedRequestCustomizer}
     * makes the request scheme/host and {@code isSecure()} reflect the {@code X-Forwarded-*} /
     * {@code Forwarded} (RFC 7239) headers from the fronting TLS-terminating reverse proxy, so
     * container-level concerns (secure-cookie flags, generated redirects) see the external HTTPS URL.
     * Package-visible so the wiring is exercised by tests.
     */
    static ServerConnector httpConnector(Server server, LwsConfiguration config) {
        HttpConfiguration httpConfig = new HttpConfiguration();
        hideServerVersion(httpConfig);
        if (config.behindProxy()) {
            httpConfig.addCustomizer(new ForwardedRequestCustomizer());
        }
        ServerConnector connector = new ServerConnector(server, new HttpConnectionFactory(httpConfig));
        connector.setPort(config.tlsEnabled() ? config.tlsHttpPort() : config.port());
        return connector;
    }

    /**
     * Build the servlet context (all LWS servlets and filters) for an {@link LwsComponents} graph.
     * Shared by {@link #main} and integration tests so both exercise identical wiring.
     */
    public static ServletContextHandler buildHandler(LwsComponents c, LwsConfiguration config) {
        return buildHandler(c, config, null, () -> false);
    }

    /**
     * As {@link #buildHandler(LwsComponents, LwsConfiguration)}, but when TLS is terminated by the
     * server it also installs (ahead of authentication) the HTTP&rarr;HTTPS redirect and the ACME
     * HTTP-01 challenge servlet, driven by {@code challenges}.
     *
     * @param httpsReady whether the HTTPS connector is up; the redirect filter answers {@code 503}
     *                   rather than a cacheable redirect until it is (finding M28)
     */
    public static ServletContextHandler buildHandler(LwsComponents c, LwsConfiguration config,
            AcmeChallengeStore challenges, java.util.function.BooleanSupplier httpsReady) {
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");

        // Session cookie hardening for the /app console. SameSite=Strict is defence in depth behind
        // Wicket's resource-isolation listener: it keeps the cookie off cross-site requests
        // entirely. HttpOnly keeps it out of reach of script. Secure only when we actually serve
        // HTTPS — setting it on a plaintext dev server would stop the cookie being sent at all.
        org.eclipse.jetty.ee10.servlet.SessionHandler sessions = context.getSessionHandler();
        sessions.setHttpOnly(true);
        sessions.setSameSite(HttpCookie.SameSite.STRICT);
        sessions.setSecureRequestOnly(config.baseUri().startsWith("https://"));
        // Jetty's default is -1 (never expire), unlike the Spring path's 30 minutes: an unbounded
        // in-memory session cache is an unauthenticated memory leak for any visitor to /app.
        sessions.setMaxInactiveInterval(1800);
        // Under a path prefix the cookie belongs to that path, not to every site on the host.
        if (!config.basePath().isEmpty()) {
            sessions.setSessionPath(config.basePath());
        }

        EnumSet<DispatcherType> req = EnumSet.of(DispatcherType.REQUEST);

        // When the server terminates TLS itself, redirect plaintext to HTTPS (leaving the ACME
        // challenge path on HTTP) and serve the HTTP-01 challenge. Installed before authentication.
        if (config.tlsEnabled() && challenges != null) {
            context.addFilter(new FilterHolder(
                    new HttpsRedirectFilter(config.tlsPort(), config.baseUri(), httpsReady)), "/*", req);
            context.addServlet(new ServletHolder(new AcmeChallengeServlet(challenges)),
                    AcmeChallengeServlet.PATH + "*");
        }
        // HSTS on the responses that actually went out over TLS, whether this server terminated it
        // or a trusted proxy did. Installed in both bootstraps; see HstsFilter (finding M28).
        HstsFilter hsts = HstsFilter.forConfig(config);
        if (hsts != null) {
            context.addFilter(new FilterHolder(hsts), "/*", req);
        }
        // CORS before authentication, because a preflight carries no credentials by definition: left
        // to reach the resource servlet it would be answered 401 or 404 and the browser would block
        // the real request behind it (finding M7). After the HTTPS redirect above, so a plaintext
        // request on a TLS-terminating server is still redirected rather than served cross-origin.
        CorsFilter cors = CorsFilter.forConfig(config);
        if (cors != null) {
            context.addFilter(new FilterHolder(cors), "/*", req);
        }

        // Filters (order matters: authentication first, then UI security, then Wicket).
        context.addFilter(new FilterHolder(c.authenticationFilter()), "/*", req);
        // Ahead of pac4j and Wicket: puts the base URI's path back into their redirects.
        BasePathRedirectFilter basePath = BasePathRedirectFilter.forConfig(config);
        if (basePath != null) {
            context.addFilter(new FilterHolder(basePath), LwsConfiguration.UI_PREFIX + "/*", req);
            context.addFilter(new FilterHolder(basePath), LwsConfiguration.CALLBACK_PATH, req);
        }
        if (c.pac4jConfig() != null) {
            context.addFilter(new FilterHolder(new SecurityFilter(c.pac4jConfig(), Pac4jSupport.CLIENT_NAME)),
                    Pac4jSupport.LOGIN_PATH, req);
            CallbackFilter callback = new CallbackFilter(c.pac4jConfig());
            callback.setDefaultUrl(config.baseUri() + Pac4jSupport.LOGIN_PATH);
            context.addFilter(new FilterHolder(callback), Pac4jSupport.CALLBACK_PATH, req);
        }
        FilterHolder wicket = new FilterHolder(new WicketFilter(new LwsWebApplication(
                c.resourceService(), config, c.aclService(), c.credentialValidator())));
        wicket.setInitParameter(WicketFilter.FILTER_MAPPING_PARAM, "/app/*");
        context.addFilter(wicket, "/app/*", req);

        // Servlets (specific mappings win over the catch-all "/*").
        context.addServlet(new ServletHolder(new StorageDescriptionServlet(c.storageDescriptionResponder())),
                config.storageDescriptionPath());
        if (c.tokenExchange() != null) {
            // The embedded authorization server (lws10-core, Authorization): its token endpoint and
            // its RFC 8414 metadata at the well-known path lws10-core registers.
            context.addServlet(new ServletHolder(
                    new TokenEndpointServlet(c.tokenExchange(), c.dpopValidator(), config)), config.tokenPath());
            context.addServlet(new ServletHolder(
                    new AuthorizationServerMetadataServlet(config, c.tokenExchange())),
                    LwsConfiguration.AS_METADATA_PATH);
        }
        context.addServlet(new ServletHolder(new SubscriptionServlet(c.subscriptionService(), config)),
                config.subscriptionsPath());
        context.addServlet(new ServletHolder(new SubscriptionServlet(c.subscriptionService(), config)),
                config.subscriptionsPath() + "/*");
        context.addServlet(new ServletHolder(new JwksServlet(c.jwkSetJson())), config.jwksPath());
        if (config.searchIndexEnabled()) {
            ServletHolder searchIndex = new ServletHolder(new SearchIndexServlet(c.searchIndexService(), config));
            context.addServlet(searchIndex, config.typeIndexPath());
            context.addServlet(searchIndex, config.typeSearchPath());
        }
        if (config.accessRequestsEnabled()) {
            ServletHolder access = new ServletHolder(new AccessServlet(
                    c.accessService(), c.resourceService(), config, c.notificationEmitter(), c.clock()));
            context.addServlet(access, config.accessRequestsPath());
            context.addServlet(access, config.accessRequestsPath() + "/*");
            context.addServlet(access, config.accessGrantsPath());
            context.addServlet(access, config.accessGrantsPath() + "/*");
        }
        context.addServlet(new ServletHolder(new LwsResourceServlet(c.resourceService(), config,
                c.aclService(), c.linksetService(), c.storageDescriptionResponder())), "/*");
        return context;
    }
}
