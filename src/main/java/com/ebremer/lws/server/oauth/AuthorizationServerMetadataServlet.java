package com.ebremer.lws.server.oauth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.http.HttpSupport;

/**
 * The embedded authorization server's metadata (RFC 8414), at {@code /.well-known/lws-configuration}
 * as lws10-core, Authorization Server Metadata, requires.
 *
 * <p>Beyond the RFC 8414 members it carries the two lws10-core defines: the
 * {@code subject_token_types_supported} the token endpoint exchanges, and the
 * {@code subject_identifier_types_supported} — {@code https}, {@code did:key} and {@code did:web},
 * the subject identifiers the authentication suites behind it can verify.
 *
 * @author Erich Bremer
 */
public final class AuthorizationServerMetadataServlet extends HttpServlet {

    private final byte[] document;

    public AuthorizationServerMetadataServlet(LwsConfiguration config, TokenExchange exchange) {
        JsonArrayBuilder subjectTokenTypes = Json.createArrayBuilder();
        exchange.subjectTokenTypes().forEach(subjectTokenTypes::add);
        JsonArrayBuilder dpopAlgs = Json.createArrayBuilder();
        for (String alg : HttpSupport.DPOP_ALGS.split(" ")) {
            dpopAlgs.add(alg);
        }
        this.document = Json.createObjectBuilder()
                .add("issuer", config.oauthIssuer())
                .add("token_endpoint", config.tokenEndpointIri())
                .add("jwks_uri", config.jwksIri())
                .add("grant_types_supported", Json.createArrayBuilder().add(TokenExchange.GRANT_TYPE))
                .add("response_types_supported", Json.createArrayBuilder().add("token"))
                .add("token_endpoint_auth_methods_supported", Json.createArrayBuilder().add("none"))
                .add("claims_supported", Json.createArrayBuilder()
                        .add("sub").add("iss").add("client_id").add("aud").add("exp").add("iat").add("jti"))
                .add("subject_token_types_supported", subjectTokenTypes)
                .add("subject_identifier_types_supported", Json.createArrayBuilder()
                        .add("https").add("did:key").add("did:web"))
                .add("dpop_signing_alg_values_supported", dpopAlgs)
                .build().toString().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String method = req.getMethod();
        if (method.equals("OPTIONS")) {
            resp.setHeader("Allow", "GET, HEAD, OPTIONS");
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        if (!method.equals("GET") && !method.equals("HEAD")) {
            resp.setHeader("Allow", "GET, HEAD, OPTIONS");
            resp.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("application/json;charset=utf-8");
        resp.setHeader("Cache-Control", "public, max-age=3600");
        resp.setContentLength(document.length);
        if (method.equals("GET")) {
            resp.getOutputStream().write(document);
        }
    }
}
