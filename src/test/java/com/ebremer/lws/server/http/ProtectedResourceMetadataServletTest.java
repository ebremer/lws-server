package com.ebremer.lws.server.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * The parts of discovery that depend on configuration rather than on a running server: which
 * authorization servers the protected resource metadata names, what happens when there are none,
 * the shape of the challenge in each case, and the URL mapping both directions of which must agree
 * (RFC 9728 section 3.1).
 *
 * @author Erich Bremer
 */
class ProtectedResourceMetadataServletTest {

    private static final String PRM = "/.well-known/oauth-protected-resource";

    private static LwsConfiguration config(String baseUri, String... properties) {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUri);
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        for (int i = 0; i + 1 < properties.length; i += 2) {
            p.setProperty(properties[i], properties[i + 1]);
        }
        return LwsConfiguration.of(p);
    }

    private static HttpServletRequest request(String method, String uri, String query) {
        HttpServletRequest r = mock(HttpServletRequest.class);
        when(r.getMethod()).thenReturn(method);
        when(r.getRequestURI()).thenReturn(uri);
        when(r.getContextPath()).thenReturn("");
        when(r.getQueryString()).thenReturn(query);
        return r;
    }

    /** A response mock that keeps what is written to it. */
    private static HttpServletResponse response(ByteArrayOutputStream body) throws Exception {
        HttpServletResponse r = mock(HttpServletResponse.class);
        when(r.getOutputStream()).thenReturn(new ServletOutputStream() {
            @Override
            public void write(int b) {
                body.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener listener) {
            }
        });
        return r;
    }

    private static JsonObject get(LwsConfiguration config, String uri) throws Exception {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpServletResponse response = response(body);
        new ProtectedResourceMetadataServlet(config).service(request("GET", uri, null), response);
        verify(response).setStatus(HttpServletResponse.SC_OK);
        try (var reader = Json.createReader(new StringReader(body.toString(StandardCharsets.UTF_8)))) {
            return reader.readObject();
        }
    }

    // ----- authorization_servers -----

    @Test
    void trustedIssuersOnlyAreListedInConfigurationOrder() throws Exception {
        LwsConfiguration config = config("https://storage.example", "lws.oauth.enabled", "false",
                "lws.oauth.trusted-issuers", "https://b.example https://a.example");
        assertEquals(List.of("https://b.example", "https://a.example"), config.authorizationServers());
        assertEquals(Json.createArrayBuilder().add("https://b.example").add("https://a.example").build(),
                get(config, PRM + "/doc").getJsonArray("authorization_servers"));
        // The first one is the legacy as_uri.
        assertEquals("Bearer resource_metadata=\"https://storage.example" + PRM + "/doc\", "
                + "as_uri=\"https://b.example\", realm=\"https://storage.example/\"",
                HttpSupport.challenge("Bearer", config, request("GET", "/doc", null), null, null));
    }

    @Test
    void theEmbeddedServerComesFirstAndNoIssuerTwice() {
        LwsConfiguration config = config("https://storage.example",
                "lws.oauth.trusted-issuers", "https://a.example https://storage.example");
        assertEquals(List.of("https://storage.example", "https://a.example"), config.authorizationServers());
        assertEquals("https://storage.example", config.primaryAuthorizationServer());
    }

    /**
     * No authorization server, no conforming document — lws10-core requires
     * {@code authorization_servers} to name one — so a 404, and challenges without
     * {@code resource_metadata} (or {@code as_uri}).
     */
    @Test
    void withNoAuthorizationServerThereIsNoMetadata() throws Exception {
        LwsConfiguration config = config("https://storage.example", "lws.oauth.enabled", "false");
        assertEquals(List.of(), config.authorizationServers());
        assertNull(config.primaryAuthorizationServer());
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpServletResponse response = response(body);
        new ProtectedResourceMetadataServlet(config).service(request("GET", PRM + "/doc", null), response);
        verify(response).setStatus(HttpServletResponse.SC_NOT_FOUND);

        HttpServletRequest refused = request("GET", "/doc", null);
        assertEquals("Bearer realm=\"https://storage.example/\"",
                HttpSupport.challenge("Bearer", config, refused, null, null));
        assertEquals("DPoP realm=\"https://storage.example/\", algs=\"" + HttpSupport.DPOP_ALGS + "\"",
                HttpSupport.challenge("DPoP", config, refused, null, null));

        LwsConfiguration bare = config("https://storage.example", "lws.oauth.enabled", "false",
                "lws.oauth.legacy-challenge", "false");
        assertEquals("Bearer", HttpSupport.challenge("Bearer", bare, refused, null, null));
        assertEquals("Bearer error=\"invalid_token\", error_description=\"x\"",
                HttpSupport.challenge("Bearer", bare, refused, "invalid_token", "x"));
    }

    // ----- the challenge -----

    @Test
    void theLegacyParametersFollowResourceMetadataAndCanBeTurnedOff() {
        HttpServletRequest refused = request("GET", "/c/x", "q=1");
        String metadata = "https://storage.example" + PRM + "/c/x?q=1";
        assertEquals("SAML2 resource_metadata=\"" + metadata + "\", realm=\"https://storage.example/\", "
                + "error=\"invalid_token\", error_description=\"no\"",
                HttpSupport.challenge("SAML2", config("https://storage.example"), refused, "invalid_token", "no"));
        LwsConfiguration current = config("https://storage.example", "lws.oauth.legacy-challenge", "false");
        assertEquals("Bearer resource_metadata=\"" + metadata + "\"",
                HttpSupport.challenge("Bearer", current, refused, null, null));
        assertEquals("DPoP resource_metadata=\"" + metadata + "\", algs=\"" + HttpSupport.DPOP_ALGS
                + "\", error=\"use_dpop_nonce\", error_description=\"a nonce is required in the DPoP proof\"",
                HttpSupport.challenge("DPoP", current, refused, "use_dpop_nonce",
                        "a nonce is required in the DPoP proof"));
    }

    // ----- the URL mapping -----

    /**
     * {@code metadataUrl} and {@code resourceIri} are inverses through the proxy: whatever URL a
     * challenge names, the request the proxy forwards for it yields the URL that was requested.
     */
    @Test
    void theMetadataUrlLeadsBackToTheRequestedUrl() {
        for (String base : new String[] {"https://storage.example", "https://host.example/lws",
                "http://localhost:8080/a/b"}) {
            LwsConfiguration config = config(base);
            String origin = base.substring(0, base.length() - config.basePath().length());
            for (String[] request : new String[][] {
                    {"/", null}, {"/", "q"}, {"/c/", null}, {"/c/x", null}, {"/c/x", "a=1&b=%20"},
                    {"/c/caf%C3%A9%20x", null}, {"/.lws/subscriptions", null}, {"/c/x", ""}}) {
                String requested = base + request[0] + (request[1] == null ? "" : "?" + request[1]);
                String url = ProtectedResourceMetadataServlet.metadataUrl(config, request[0], request[1]);
                String expectedPrefix = origin + PRM + config.basePath();
                assertEquals(true, url.startsWith(expectedPrefix), url);
                // The proxy strips the base path from what follows the well-known path.
                String forwarded = url.substring(origin.length() + PRM.length() + config.basePath().length());
                int q = forwarded.indexOf('?');
                String suffix = q < 0 ? forwarded : forwarded.substring(0, q);
                String query = q < 0 ? null : forwarded.substring(q + 1);
                assertEquals(requested, ProtectedResourceMetadataServlet.resourceIri(config, suffix, query),
                        base + " " + request[0] + " via " + url);
            }
        }
        // RFC 9728 section 3.1: the slash after the host is dropped, the query kept.
        assertEquals("https://storage.example" + PRM,
                ProtectedResourceMetadataServlet.metadataUrl(config("https://storage.example"), "/", null));
        assertEquals("https://storage.example" + PRM + "?q",
                ProtectedResourceMetadataServlet.metadataUrl(config("https://storage.example/"), "/", "q"));
        assertEquals("https://host.example" + PRM + "/lws/",
                ProtectedResourceMetadataServlet.metadataUrl(config("https://host.example/lws"), "/", null));
    }

    /** A URI that does not literally continue the well-known path is no metadata URL. */
    @Test
    void aSpellingThatOnlyDecodesToTheWellKnownPathIsNotFound() throws Exception {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpServletResponse response = response(body);
        new ProtectedResourceMetadataServlet(config("https://storage.example"))
                .service(request("GET", "/.well-known/oauth-protected-resourc%65/doc", null), response);
        verify(response).setStatus(HttpServletResponse.SC_NOT_FOUND);
    }
}
