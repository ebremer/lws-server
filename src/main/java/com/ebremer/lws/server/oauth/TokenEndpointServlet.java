package com.ebremer.lws.server.oauth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import jakarta.json.Json;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.DpopValidator;
import com.ebremer.lws.server.rdf.RdfFormats;

/**
 * The embedded authorization server's token endpoint: {@code POST} an
 * {@code application/x-www-form-urlencoded} token-exchange request (RFC 8693), receive an access
 * token for this storage (lws10-core, Token Exchange). See {@link TokenExchange} for what is checked
 * and what is issued.
 *
 * <p>Clients are public: lws10-core identifies a client by the URI in its credential, not by a
 * registration here, so no client authentication is asked for. A request that carries a
 * {@code DPoP} proof (RFC 9449 §5) gets a token bound to the proof's key. Every response — success or
 * error — is {@code application/json} and {@code Cache-Control: no-store} (RFC 6749 §5.1).
 *
 * @author Erich Bremer
 */
public final class TokenEndpointServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(TokenEndpointServlet.class);

    private static final String FORM = "application/x-www-form-urlencoded";

    private final transient TokenExchange exchange;
    private final transient DpopValidator dpop;
    private final transient LwsConfiguration config;

    public TokenEndpointServlet(TokenExchange exchange, DpopValidator dpop, LwsConfiguration config) {
        this.exchange = exchange;
        this.dpop = dpop;
        this.config = config;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        switch (req.getMethod()) {
            case "POST" -> token(req, resp);
            case "OPTIONS" -> {
                resp.setHeader("Allow", "POST, OPTIONS");
                resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }
            default -> {
                resp.setHeader("Allow", "POST, OPTIONS");
                error(resp, new TokenExchange.OAuthError(405, "invalid_request", "use POST"));
            }
        }
    }

    private void token(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            String contentType = req.getContentType();
            if (contentType == null || !RdfFormats.stripParameters(contentType).equals(FORM)) {
                throw new TokenExchange.OAuthError(400, "invalid_request", "the body must be " + FORM);
            }
            Map<String, String> params = new LinkedHashMap<>();
            for (Map.Entry<String, String[]> entry : req.getParameterMap().entrySet()) {
                if (entry.getValue().length != 1) {
                    // RFC 6749 §3.2: request parameters MUST NOT be included more than once.
                    throw new TokenExchange.OAuthError(400, "invalid_request",
                            entry.getKey() + " is included more than once");
                }
                params.put(entry.getKey(), entry.getValue()[0]);
            }
            String proof = req.getHeader("DPoP");
            String jkt = null;
            if (proof != null && !proof.isBlank()) {
                Optional<String> verified = dpop.verifyTokenRequestProof("POST", config.tokenEndpointIri(), proof);
                if (verified.isEmpty()) {
                    throw new TokenExchange.OAuthError(400, "invalid_dpop_proof", "the DPoP proof is not valid");
                }
                jkt = verified.get();
            }
            TokenExchange.Issued issued = exchange.exchange(params, jkt);
            if (jkt != null && !dpop.claimProof(proof)) {
                throw new TokenExchange.OAuthError(400, "invalid_dpop_proof", "this DPoP proof has already been used");
            }
            byte[] body = Json.createObjectBuilder()
                    .add("access_token", issued.accessToken())
                    .add("issued_token_type", TokenExchange.TYPE_ACCESS_TOKEN)
                    .add("token_type", issued.tokenType())
                    .add("expires_in", issued.expiresIn())
                    .build().toString().getBytes(StandardCharsets.UTF_8);
            resp.setStatus(HttpServletResponse.SC_OK);
            noStore(resp);
            resp.setContentType("application/json;charset=utf-8");
            resp.setContentLength(body.length);
            resp.getOutputStream().write(body);
        } catch (TokenExchange.OAuthError e) {
            error(resp, e);
        } catch (RuntimeException e) {
            log.error("Token request failed", e);
            error(resp, new TokenExchange.OAuthError(500, "server_error", "internal error"));
        }
    }

    private static void error(HttpServletResponse resp, TokenExchange.OAuthError e) throws IOException {
        if (resp.isCommitted()) {
            return;
        }
        byte[] body = Json.createObjectBuilder()
                .add("error", e.error())
                .add("error_description", e.getMessage() == null ? "" : e.getMessage())
                .build().toString().getBytes(StandardCharsets.UTF_8);
        resp.setStatus(e.status());
        noStore(resp);
        resp.setContentType("application/json;charset=utf-8");
        resp.setContentLength(body.length);
        resp.getOutputStream().write(body);
    }

    private static void noStore(HttpServletResponse resp) {
        resp.setHeader("Cache-Control", "no-store");
        resp.setHeader("Pragma", "no-cache");
    }
}
