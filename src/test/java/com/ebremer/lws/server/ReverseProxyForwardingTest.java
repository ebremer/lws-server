package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Properties;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.junit.jupiter.api.Test;

/**
 * Verifies the connector wiring for running behind a TLS-terminating reverse proxy: with
 * {@code lws.behind-proxy} the server trusts {@code X-Forwarded-Proto} (so request scheme /
 * {@code isSecure()} reflect the external HTTPS URL); without it, a client cannot spoof the scheme.
 *
 * @author Erich Bremer
 */
class ReverseProxyForwardingTest {

    private static final HttpClient http = HttpClient.newHttpClient();

    @Test
    void honoursForwardedProtoWhenBehindProxy() throws Exception {
        assertEquals("https true", schemeSeenByServer(true));
    }

    @Test
    void ignoresForwardedProtoByDefault() throws Exception {
        assertEquals("http false", schemeSeenByServer(false));
    }

    /**
     * Start a server (optionally behind-proxy) on an ephemeral port via the production connector
     * factory, GET {@code /echo} with {@code X-Forwarded-Proto: https}, and return what the servlet
     * observed as {@code "<scheme> <isSecure>"}.
     */
    private static String schemeSeenByServer(boolean behindProxy) throws Exception {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", "https://storage.example");
        p.setProperty("lws.behind-proxy", String.valueOf(behindProxy));
        LwsConfiguration config = LwsConfiguration.of(p);

        Server server = new Server();
        ServerConnector connector = JettyLauncher.httpConnector(server, config);
        connector.setPort(0); // ephemeral
        server.addConnector(connector);
        ServletContextHandler ctx = new ServletContextHandler();
        ctx.setContextPath("/");
        ctx.addServlet(new ServletHolder(new HttpServlet() {
            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                resp.getWriter().write(req.getScheme() + " " + req.isSecure());
            }
        }), "/echo");
        server.setHandler(ctx);
        server.start();
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(
                            URI.create("http://localhost:" + connector.getLocalPort() + "/echo"))
                    .header("X-Forwarded-Proto", "https").build(), HttpResponse.BodyHandlers.ofString());
            return r.body();
        } finally {
            server.stop();
        }
    }
}
