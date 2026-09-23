package com.ebremer.lws.server;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServlet;
import org.apache.wicket.protocol.http.WicketFilter;
import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.ForwardedRequestCustomizer;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.pac4j.jee.filter.CallbackFilter;
import org.pac4j.jee.filter.SecurityFilter;
import org.springframework.boot.web.embedded.jetty.JettyServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.server.AbstractServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import com.ebremer.lws.server.tls.HstsFilter;
import com.ebremer.lws.server.ui.LwsWebApplication;

/**
 * The single Spring-aware class in the server. It does nothing but build the framework-free
 * {@link LwsComponents} graph and register its plain Jakarta servlets and filters with the
 * embedded Jetty container, and align the HTTP port with the configured base IRI.
 *
 * <p>Everything here has a direct, annotation-free analogue in {@code JettyLauncher}; migrating
 * off Spring Boot means deleting this class (and the {@code @SpringBootApplication} main) and
 * using that launcher instead.
 *
 * @author Erich Bremer
 */
@Configuration
public class LwsServletConfig {

    private static final Logger log = LoggerFactory.getLogger(LwsServletConfig.class);

    @Bean(destroyMethod = "close")
    public LwsComponents lwsComponents() {
        LwsConfiguration config = LwsConfiguration.load();
        warnIfTlsIsConfiguredButUnused(config);
        return LwsComponents.create(config);
    }

    /**
     * This entry point does not terminate TLS, and it is the one the README calls the default.
     *
     * <p>{@code lws.tls.*} — the self-terminated HTTPS connector, the ACME certificate manager and
     * the HTTP-to-HTTPS redirect — are read and acted on only by {@link JettyLauncher}. Under Spring
     * Boot they were silently ignored: an operator who set {@code lws.tls.enabled=true}, restarted,
     * and saw the server come up had every reason to believe it was serving HTTPS, and it was
     * serving plaintext on the HTTP port (finding L58). Nothing said otherwise. Now something does.
     */
    private static void warnIfTlsIsConfiguredButUnused(LwsConfiguration config) {
        if (config.tlsEnabled()) {
            log.warn("lws.tls.enabled=true is IGNORED by this entry point: the Spring Boot bootstrap "
                    + "serves plaintext HTTP on port {} and terminates no TLS. Run the JettyLauncher "
                    + "main (com.ebremer.lws.server.JettyLauncher) for built-in TLS, or terminate "
                    + "TLS at a reverse proxy and set lws.behind-proxy=true.", config.port());
        }
    }

    @Bean
    public WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> serverCustomizer(LwsComponents components) {
        return factory -> {
            factory.setPort(components.config().port());
            // Under a path prefix the console's session cookie belongs to that path, not to the
            // whole host, which may be serving other sites that have no business receiving it.
            if (!components.config().basePath().isEmpty() && factory instanceof AbstractServletWebServerFactory a) {
                a.getSession().getCookie().setPath(components.config().basePath());
            }
            // Behind a TLS-terminating reverse proxy, add Jetty's ForwardedRequestCustomizer so the
            // request scheme/host and isSecure() reflect the X-Forwarded-* / Forwarded (RFC 7239)
            // headers from the proxy (mirrors JettyLauncher.httpConnector for the bare-Jetty path).
            if (components.config().behindProxy() && factory instanceof JettyServletWebServerFactory jetty) {
                jetty.addServerCustomizers(server -> {
                    for (org.eclipse.jetty.server.Connector connector : server.getConnectors()) {
                        for (ConnectionFactory cf : connector.getConnectionFactories()) {
                            if (cf instanceof HttpConnectionFactory http) {
                                http.getHttpConfiguration().addCustomizer(new ForwardedRequestCustomizer());
                            }
                        }
                    }
                });
            }
        };
    }

    @Bean
    public ServletRegistrationBean<LwsResourceServlet> resourceServlet(LwsComponents c) {
        ServletRegistrationBean<LwsResourceServlet> bean = new ServletRegistrationBean<>(
                new LwsResourceServlet(c.resourceService(), c.config(), c.aclService(), c.linksetService(),
                        c.storageDescriptionResponder()), "/*");
        bean.setName("lwsResource");
        bean.setLoadOnStartup(1);
        return bean;
    }

    @Bean
    public ServletRegistrationBean<StorageDescriptionServlet> storageDescriptionServlet(LwsComponents c) {
        ServletRegistrationBean<StorageDescriptionServlet> bean = new ServletRegistrationBean<>(
                new StorageDescriptionServlet(c.storageDescriptionResponder()),
                c.config().storageDescriptionPath());
        bean.setName("lwsStorageDescription");
        return bean;
    }

    /**
     * The embedded authorization server's token endpoint (lws10-core, Token Exchange). When the
     * server is off the registration is disabled, and holds a placeholder because Spring will not
     * register a null servlet.
     */
    @Bean
    public ServletRegistrationBean<HttpServlet> tokenEndpointServlet(LwsComponents c) {
        HttpServlet servlet = c.tokenExchange() == null ? new HttpServlet() { }
                : new TokenEndpointServlet(c.tokenExchange(), c.dpopValidator(), c.config());
        ServletRegistrationBean<HttpServlet> bean = new ServletRegistrationBean<>(servlet, c.config().tokenPath());
        bean.setName("lwsToken");
        bean.setEnabled(c.tokenExchange() != null);
        return bean;
    }

    /** The embedded authorization server's metadata at {@code /.well-known/lws-configuration}. */
    @Bean
    public ServletRegistrationBean<HttpServlet> authorizationServerMetadataServlet(LwsComponents c) {
        HttpServlet servlet = c.tokenExchange() == null ? new HttpServlet() { }
                : new AuthorizationServerMetadataServlet(c.config(), c.tokenExchange());
        ServletRegistrationBean<HttpServlet> bean =
                new ServletRegistrationBean<>(servlet, LwsConfiguration.AS_METADATA_PATH);
        bean.setName("lwsAuthorizationServerMetadata");
        bean.setEnabled(c.tokenExchange() != null);
        return bean;
    }

    @Bean
    public ServletRegistrationBean<SubscriptionServlet> subscriptionServlet(LwsComponents c) {
        ServletRegistrationBean<SubscriptionServlet> bean = new ServletRegistrationBean<>(
                new SubscriptionServlet(c.subscriptionService(), c.config()),
                c.config().subscriptionsPath(), c.config().subscriptionsPath() + "/*");
        bean.setName("lwsSubscriptions");
        return bean;
    }

    @Bean
    public ServletRegistrationBean<JwksServlet> jwksServlet(LwsComponents c) {
        ServletRegistrationBean<JwksServlet> bean = new ServletRegistrationBean<>(
                new JwksServlet(c.jwkSetJson()), c.config().jwksPath());
        bean.setName("lwsJwks");
        return bean;
    }

    @Bean
    public ServletRegistrationBean<SearchIndexServlet> searchIndexServlet(LwsComponents c) {
        ServletRegistrationBean<SearchIndexServlet> bean = new ServletRegistrationBean<>(
                new SearchIndexServlet(c.searchIndexService(), c.config()),
                c.config().typeIndexPath(), c.config().typeSearchPath());
        bean.setName("lwsSearchIndex");
        bean.setEnabled(c.config().searchIndexEnabled());
        return bean;
    }

    @Bean
    public ServletRegistrationBean<AccessServlet> accessServlet(LwsComponents c) {
        ServletRegistrationBean<AccessServlet> bean = new ServletRegistrationBean<>(
                new AccessServlet(c.accessService(), c.resourceService(), c.config(),
                        c.notificationEmitter(), c.clock()),
                c.config().accessRequestsPath(), c.config().accessRequestsPath() + "/*",
                c.config().accessGrantsPath(), c.config().accessGrantsPath() + "/*");
        bean.setName("lwsAccess");
        bean.setEnabled(c.config().accessRequestsEnabled());
        return bean;
    }

    /**
     * {@code Strict-Transport-Security} on responses served over TLS.
     *
     * <p>This entry point terminates no TLS, which is precisely why the filter belongs here: the
     * documented production posture is a reverse proxy in front of it, so {@code isSecure()} is true
     * (via {@code ForwardedRequestCustomizer}, wired above when {@code lws.behind-proxy=true}) and
     * these responses are the ones a browser sees over HTTPS. Before this, HSTS existed only on the
     * bare-Jetty launcher's plaintext redirect, where RFC 6797 requires user agents to ignore it —
     * so the default deployment emitted none at all (finding M28).
     */
    @Bean
    public FilterRegistrationBean<Filter> hstsFilter(LwsComponents c) {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>();
        HstsFilter filter = HstsFilter.forConfig(c.config());
        if (filter == null) {
            bean.setFilter((req, res, chain) -> chain.doFilter(req, res));
            bean.setEnabled(false);
            return bean;
        }
        bean.setFilter(filter);
        bean.addUrlPatterns("/*");
        bean.setOrder(0); // before authentication, so the header is set whatever the outcome
        bean.setName("lwsHsts");
        return bean;
    }

    /**
     * Cross-origin access for browser applications (finding M7).
     *
     * <p>Ordered ahead of {@link #authenticationFilter}: a CORS preflight carries no credentials by
     * definition, so if it reached the resource servlet it would be answered {@code 401} or
     * {@code 404} and the browser would block the real request behind it. Not registered at all
     * unless {@code lws.cors.allowed-origins} names something.
     */
    @Bean
    public FilterRegistrationBean<Filter> corsFilter(LwsComponents c) {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>();
        CorsFilter filter = CorsFilter.forConfig(c.config());
        if (filter == null) {
            bean.setFilter((req, res, chain) -> chain.doFilter(req, res));
            bean.setEnabled(false);
            return bean;
        }
        bean.setFilter(filter);
        bean.addUrlPatterns("/*");
        bean.setOrder(0);
        bean.setName("lwsCors");
        return bean;
    }

    @Bean
    public FilterRegistrationBean<Filter> authenticationFilter(LwsComponents c) {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>(c.authenticationFilter());
        bean.addUrlPatterns("/*");
        bean.setOrder(1);
        bean.setName("lwsAuth");
        return bean;
    }

    /**
     * Keeps the console's redirects under the path of {@code lws.base-uri} when a proxy strips it.
     * Ahead of pac4j and Wicket, whose redirects it rewrites; not registered at the root of a host.
     */
    @Bean
    public FilterRegistrationBean<Filter> basePathRedirectFilter(LwsComponents c) {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>();
        BasePathRedirectFilter filter = BasePathRedirectFilter.forConfig(c.config());
        if (filter == null) {
            bean.setFilter((req, res, chain) -> chain.doFilter(req, res));
            bean.setEnabled(false);
            return bean;
        }
        bean.setFilter(filter);
        bean.addUrlPatterns(LwsConfiguration.UI_PREFIX + "/*", LwsConfiguration.CALLBACK_PATH);
        bean.setOrder(1);
        bean.setName("lwsBasePathRedirect");
        return bean;
    }

    @Bean
    public FilterRegistrationBean<Filter> wicketFilter(LwsComponents c) {
        WicketFilter filter = new WicketFilter(new LwsWebApplication(
                c.resourceService(), c.config(), c.aclService(), c.credentialValidator()));
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>(filter);
        bean.addUrlPatterns("/app/*");
        bean.addInitParameter(WicketFilter.FILTER_MAPPING_PARAM, "/app/*");
        bean.setOrder(3);
        bean.setName("wicket");
        return bean;
    }

    @Bean
    public FilterRegistrationBean<Filter> pac4jSecurityFilter(LwsComponents c) {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>();
        if (c.pac4jConfig() != null) {
            bean.setFilter(new SecurityFilter(c.pac4jConfig(), Pac4jSupport.CLIENT_NAME));
            bean.addUrlPatterns(Pac4jSupport.LOGIN_PATH); // only the OIDC trigger path, not the whole UI
            bean.setOrder(2);
            bean.setName("pac4jSecurity");
        } else {
            bean.setFilter((req, res, chain) -> chain.doFilter(req, res));
            bean.setEnabled(false);
        }
        return bean;
    }

    @Bean
    public FilterRegistrationBean<Filter> pac4jCallbackFilter(LwsComponents c) {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>();
        if (c.pac4jConfig() != null) {
            CallbackFilter filter = new CallbackFilter(c.pac4jConfig());
            filter.setDefaultUrl(c.config().baseUri() + Pac4jSupport.LOGIN_PATH);
            bean.setFilter(filter);
            bean.addUrlPatterns(Pac4jSupport.CALLBACK_PATH);
            bean.setOrder(2);
            bean.setName("pac4jCallback");
        } else {
            bean.setFilter((req, res, chain) -> chain.doFilter(req, res));
            bean.setEnabled(false);
        }
        return bean;
    }
}
