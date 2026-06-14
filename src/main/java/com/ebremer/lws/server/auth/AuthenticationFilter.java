package com.ebremer.lws.server.auth;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.RequestContext;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Resource-server authentication filter. It reads the credential from the {@code Authorization}
 * header and authenticates it:
 * <ul>
 *   <li>{@code Bearer}/{@code SAML2}: the value is validated by the credential suites;</li>
 *   <li>{@code DPoP}: in addition to validating the access token, the {@code DPoP} proof header is
 *       verified (RFC 9449) and the access token's {@code cnf.jkt} must match the proof key;</li>
 *   <li>a valid credential binds a Shiro {@link Subject} and exposes the {@link LwsPrincipal} as a
 *       request attribute; an invalid one yields {@code 401} with {@code WWW-Authenticate};</li>
 *   <li>no credential proceeds anonymously (authorization is enforced per-resource downstream).</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class AuthenticationFilter implements Filter {

    /** Request attribute under which the authenticated {@link LwsPrincipal} (if any) is stored. */
    public static final String PRINCIPAL_ATTR = "com.ebremer.lws.server.principal";

    private final LwsCredentialValidator validator;
    private final DpopValidator dpop;
    private final LwsConfiguration config;
    private final SecurityManager securityManager;

    public AuthenticationFilter(LwsCredentialValidator validator, DpopValidator dpop,
            LwsConfiguration config, SecurityManager securityManager) {
        this.validator = validator;
        this.dpop = dpop;
        this.config = config;
        this.securityManager = securityManager;
    }

    /** Read the authenticated principal from a request, or {@code null} if anonymous. */
    public static LwsPrincipal principal(HttpServletRequest request) {
        Object attr = request.getAttribute(PRINCIPAL_ATTR);
        return attr instanceof LwsPrincipal p ? p : null;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        RequestContext.setOrigin(request.getHeader("Origin"));
        RequestContext.setPurposes(parsePurposes(request.getHeader("LWS-Purpose")));
        try {
            LwsPrincipal principal = authenticate(request, response);
            if (response.isCommitted()) {
                return; // a credential was presented and rejected (401 already sent)
            }
            if (principal == null) {
                chain.doFilter(req, res);
                return;
            }
            Subject subject = new Subject.Builder(securityManager).buildSubject();
            ThreadContext.bind(subject);
            try {
                subject.login(new LwsAuthenticationToken(principal));
                request.setAttribute(PRINCIPAL_ATTR, principal);
                chain.doFilter(req, res);
            } catch (org.apache.shiro.authc.AuthenticationException e) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
            } finally {
                ThreadContext.unbindSubject();
            }
        } finally {
            RequestContext.clear();
        }
    }

    /** Parse the {@code LWS-Purpose} header (comma/space-separated purpose URIs) into a set. */
    private static Set<String> parsePurposes(String header) {
        if (header == null || header.isBlank()) {
            return Set.of();
        }
        Set<String> purposes = new LinkedHashSet<>();
        for (String token : header.split("[,\\s]+")) {
            if (!token.isBlank()) {
                purposes.add(token.trim());
            }
        }
        return purposes;
    }

    private LwsPrincipal authenticate(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String header = request.getHeader("Authorization");
        if (header == null) {
            return null;
        }
        String h = header.trim();
        int sp = h.indexOf(' ');
        if (sp <= 0) {
            return null;
        }
        String scheme = h.substring(0, sp);
        String value = h.substring(sp + 1).trim();
        if (value.isEmpty()) {
            return null;
        }
        if (scheme.equalsIgnoreCase("DPoP")) {
            return authenticateDpop(request, response, value);
        }
        if (scheme.equalsIgnoreCase("Bearer") || scheme.equalsIgnoreCase("SAML2")) {
            Optional<LwsPrincipal> validated = validator.validate(value);
            if (validated.isEmpty()) {
                unauthorized(response, "Bearer", "invalid or expired credential");
                return null;
            }
            return validated.get();
        }
        return null; // unrecognized scheme -> anonymous
    }

    private LwsPrincipal authenticateDpop(HttpServletRequest request, HttpServletResponse response,
            String accessToken) throws IOException {
        String proof = request.getHeader("DPoP");
        if (proof == null || proof.isBlank()) {
            unauthorized(response, "DPoP", "a DPoP proof header is required");
            return null;
        }
        String htu = config.baseUri() + path(request);
        Optional<String> jkt = dpop.verifyProof(request.getMethod(), htu, proof, accessToken);
        if (jkt.isEmpty()) {
            unauthorized(response, "DPoP", "invalid DPoP proof");
            return null;
        }
        if (dpop.nonceRequired() && !dpop.isNonceValid(proof)) {
            dpopNonceChallenge(response);
            return null;
        }
        Optional<LwsPrincipal> validated = validator.validate(accessToken);
        if (validated.isEmpty()) {
            unauthorized(response, "DPoP", "invalid or expired access token");
            return null;
        }
        if (!DpopValidator.isBoundTo(accessToken, jkt.get())) {
            unauthorized(response, "DPoP", "access token is not bound to the DPoP key");
            return null;
        }
        return validated.get();
    }

    /** Challenge the client to repeat the request with a server-issued nonce (RFC 9449 §8). */
    private void dpopNonceChallenge(HttpServletResponse response) throws IOException {
        response.setHeader("DPoP-Nonce", dpop.issueNonce());
        response.setHeader("WWW-Authenticate", "DPoP realm=\"lws\", error=\"use_dpop_nonce\", "
                + "error_description=\"a nonce is required in the DPoP proof\"");
        response.addHeader("Link",
                "<" + config.storageDescriptionIri() + ">; rel=\"" + LWS.storageDescription.getURI() + "\"");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "use_dpop_nonce");
    }

    private void unauthorized(HttpServletResponse response, String scheme, String description)
            throws IOException {
        response.setHeader("WWW-Authenticate",
                scheme + " realm=\"lws\", error=\"invalid_token\", error_description=\"" + description + "\"");
        // Point clients at the storage description so they can discover how to authenticate.
        response.addHeader("Link",
                "<" + config.storageDescriptionIri() + ">; rel=\"" + LWS.storageDescription.getURI() + "\"");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, description);
    }

    private static String path(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String ctx = request.getContextPath();
        String p = (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) ? uri.substring(ctx.length()) : uri;
        return p.isEmpty() ? "/" : p;
    }
}
