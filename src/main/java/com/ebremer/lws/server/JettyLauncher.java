package com.ebremer.lws.server;

import java.security.KeyStore;
import java.util.EnumSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import jakarta.servlet.DispatcherType;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
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
import com.ebremer.lws.server.http.JwksServlet;
import com.ebremer.lws.server.http.LwsResourceServlet;
import com.ebremer.lws.server.http.SearchIndexServlet;
import com.ebremer.lws.server.http.StorageDescriptionServlet;
import com.ebremer.lws.server.http.SubscriptionServlet;
import com.ebremer.lws.server.tls.AcmeCertificateManager;
import com.ebremer.lws.server.tls.AcmeChallengeServlet;
import com.ebremer.lws.server.tls.AcmeChallengeStore;
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

        Server server = new Server();
        server.addConnector(httpConnector(server, config));
        server.setHandler(buildHandler(c, config, challenges));

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
            enableTls(server, config, challenges, renewals);
        }
        log.info("LWS server (bare Jetty) listening on {}", config.baseUri());
        server.join();
    }

    /**
     * With the HTTP connector already up (so the ACME server can reach the HTTP-01 challenge),
     * obtain a certificate, start the HTTPS connector from it, and schedule periodic renewal with a
     * live reload of the {@code SslContextFactory}.
     */
    private static void enableTls(Server server, LwsConfiguration config, AcmeChallengeStore challenges,
            ScheduledExecutorService renewals) throws Exception {
        AcmeCertificateManager acme = new AcmeCertificateManager(config, challenges);
        SslContextFactory.Server ssl = newSslContextFactory(acme.obtainKeyStore(), acme.keystorePassword());
        ServerConnector https = httpsConnector(server, config, ssl);
        server.addConnector(https);
        https.start(); // the server is already running, so the new connector is started explicitly
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
        httpsConfig.addCustomizer(new SecureRequestCustomizer());
        if (config.behindProxy()) {
            httpsConfig.addCustomizer(new ForwardedRequestCustomizer());
        }
        ServerConnector connector = new ServerConnector(server,
                new SslConnectionFactory(ssl, "http/1.1"), new HttpConnectionFactory(httpsConfig));
        connector.setPort(config.tlsPort());
        return connector;
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
        return buildHandler(c, config, null);
    }

    /**
     * As {@link #buildHandler(LwsComponents, LwsConfiguration)}, but when TLS is terminated by the
     * server it also installs (ahead of authentication) the HTTP&rarr;HTTPS redirect and the ACME
     * HTTP-01 challenge servlet, driven by {@code challenges}.
     */
    public static ServletContextHandler buildHandler(LwsComponents c, LwsConfiguration config,
            AcmeChallengeStore challenges) {
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");

        EnumSet<DispatcherType> req = EnumSet.of(DispatcherType.REQUEST);

        // When the server terminates TLS itself, redirect plaintext to HTTPS (leaving the ACME
        // challenge path on HTTP) and serve the HTTP-01 challenge. Installed before authentication.
        if (config.tlsEnabled() && challenges != null) {
            context.addFilter(new FilterHolder(new HttpsRedirectFilter(config.tlsPort())), "/*", req);
            context.addServlet(new ServletHolder(new AcmeChallengeServlet(challenges)),
                    AcmeChallengeServlet.PATH + "*");
        }

        // Filters (order matters: authentication first, then UI security, then Wicket).
        context.addFilter(new FilterHolder(c.authenticationFilter()), "/*", req);
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
        context.addServlet(new ServletHolder(
                new StorageDescriptionServlet(c.storageDescriptionService(), config, c.clock())),
                config.storageDescriptionPath());
        context.addServlet(new ServletHolder(new SubscriptionServlet(c.subscriptionService(), config)),
                config.subscriptionsPath());
        context.addServlet(new ServletHolder(new SubscriptionServlet(c.subscriptionService(), config)),
                config.subscriptionsPath() + "/*");
        context.addServlet(new ServletHolder(new JwksServlet(c.webhookKeys())), config.jwksPath());
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
        context.addServlet(new ServletHolder(
                new LwsResourceServlet(c.resourceService(), config, c.aclService(), c.linksetService())), "/*");
        return context;
    }
}
