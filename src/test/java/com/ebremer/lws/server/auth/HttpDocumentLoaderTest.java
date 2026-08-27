package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import com.sun.net.httpserver.HttpServer;
import org.apache.jena.rdf.model.Model;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Tests that {@link HttpDocumentLoader} applies the {@link OutboundFetchPolicy} to redirect
 * targets, not just to the URL it was handed.
 *
 * <p>This is the SSRF hole a policy check alone does not close: an attacker-supplied URL on a
 * perfectly ordinary public host answers {@code 302} pointing at an internal address, and an HTTP
 * client left to follow redirects itself fetches it without the policy ever seeing it. The loader
 * therefore follows redirects manually and re-checks every hop.
 *
 * @author Erich Bremer
 */
class HttpDocumentLoaderTest {

    private static HttpServer server;
    private static int port;

    /** Permits the hop-1 host by name, but blocks anything resolving to a loopback address. */
    private static final OutboundFetchPolicy GUARDED = new OutboundFetchPolicy(true, Set.of("localhost"));

    @BeforeAll
    static void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        port = server.getAddress().getPort();

        // Hop 1: a host the policy allows, redirecting to an address it does not.
        server.createContext("/redirect-to-internal", exchange -> {
            exchange.getResponseHeaders().set("Location", "http://127.0.0.1:" + port + "/internal");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        // Hop 1: a redirect that stays on the allowed host.
        server.createContext("/redirect-to-allowed", exchange -> {
            exchange.getResponseHeaders().set("Location", "http://localhost:" + port + "/internal");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/internal", exchange -> respond(exchange, "text/turtle",
                "<http://example.org/s> <http://example.org/p> \"secret\" ."));
        // A redirect loop, to prove the hop cap terminates.
        server.createContext("/loop", exchange -> {
            exchange.getResponseHeaders().set("Location", "http://localhost:" + port + "/loop");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.start();
    }

    @AfterAll
    static void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String contentType, String body)
            throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @Test
    void refusesARedirectIntoABlockedAddress() {
        HttpDocumentLoader loader = new HttpDocumentLoader(GUARDED);

        // Sanity: the destination really is reachable and the loader really works, when the URL
        // presented to it is on the allowed host.
        assertNotNull(loader.load("http://localhost:" + port + "/internal"),
                "the loader should retrieve a document on an allowed host");

        // The same content, reached by a redirect from an allowed host to a blocked one.
        assertNull(loader.load("http://localhost:" + port + "/redirect-to-internal"),
                "a redirect into a blocked address must be refused, not followed");
        assertNull(loader.loadRdf("http://localhost:" + port + "/redirect-to-internal"),
                "the RDF path must refuse the same redirect");
    }

    @Test
    void followsARedirectThatStaysWithinPolicy() {
        HttpDocumentLoader loader = new HttpDocumentLoader(GUARDED);
        String body = loader.load("http://localhost:" + port + "/redirect-to-allowed");
        assertNotNull(body, "a redirect to a permitted host should still be followed");
        assertTrue(body.contains("secret"));
    }

    @Test
    void parsesRdfUsingTheResponseContentType() {
        HttpDocumentLoader loader = new HttpDocumentLoader(OutboundFetchPolicy.permitAll());
        Model model = loader.loadRdf("http://localhost:" + port + "/internal");
        assertNotNull(model, "a text/turtle response should be parsed as Turtle");
        assertEquals(1, model.size());
    }

    @Test
    void givesUpOnARedirectLoop() {
        HttpDocumentLoader loader = new HttpDocumentLoader(OutboundFetchPolicy.permitAll());
        assertNull(loader.load("http://localhost:" + port + "/loop"),
                "the hop cap must terminate a redirect loop");
    }
}
