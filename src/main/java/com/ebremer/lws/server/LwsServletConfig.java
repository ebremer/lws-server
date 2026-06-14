package com.ebremer.lws.server;

import jakarta.servlet.Filter;
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
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.ebremer.lws.server.auth.Pac4jSupport;
import com.ebremer.lws.server.http.AccessServlet;
import com.ebremer.lws.server.http.JwksServlet;
import com.ebremer.lws.server.http.LwsResourceServlet;
import com.ebremer.lws.server.http.SearchIndexServlet;
import com.ebremer.lws.server.http.StorageDescriptionServlet;
import com.ebremer.lws.server.http.SubscriptionServlet;
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

    @Bean(destroyMethod = "close")
    public LwsComponents lwsComponents() {
        return LwsComponents.create(LwsConfiguration.load());
    }

    @Bean
    public WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> serverCustomizer(LwsComponents components) {
        return factory -> {
            factory.setPort(components.config().port());
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
                new LwsResourceServlet(c.resourceService(), c.config(), c.aclService(), c.linksetService()), "/*");
        bean.setName("lwsResource");
        bean.setLoadOnStartup(1);
        return bean;
    }

    @Bean
    public ServletRegistrationBean<StorageDescriptionServlet> storageDescriptionServlet(LwsComponents c) {
        ServletRegistrationBean<StorageDescriptionServlet> bean = new ServletRegistrationBean<>(
                new StorageDescriptionServlet(c.storageDescriptionService(), c.config(), c.clock()),
                c.config().storageDescriptionPath());
        bean.setName("lwsStorageDescription");
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
                new JwksServlet(c.webhookKeys()), c.config().jwksPath());
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

    @Bean
    public FilterRegistrationBean<Filter> authenticationFilter(LwsComponents c) {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>(c.authenticationFilter());
        bean.addUrlPatterns("/*");
        bean.setOrder(1);
        bean.setName("lwsAuth");
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
