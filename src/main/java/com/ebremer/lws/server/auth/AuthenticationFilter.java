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
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.RequestContext;
import com.ebremer.lws.server.http.HttpSupport;

/**
 * Resource-server authentication filter. It reads the credential from the {@code Authorization}
 * header and authenticates it:
 * <ul>
 *   <li>{@code Bearer}/{@code SAML2}: the value is validated by the credential suites. A
 *       sender-constrained ({@code cnf.jkt}-bearing) access token is refused here — RFC 9449 §7.1
 *       requires it to be presented under the {@code DPoP} scheme with a proof — and, when
 *       {@code lws.dpop.require} is set, {@code Bearer} is refused outright;</li>
 *   <li>{@code DPoP}: in addition to validating the access token, the {@code DPoP} proof header is
 *       verified (RFC 9449) and the access token's {@code cnf.jkt} must match the proof key;</li>
 *   <li>a valid credential exposes the {@link LwsPrincipal} as a request attribute; an invalid one
 *       yields {@code 401} with {@code WWW-Authenticate};</li>
 *   <li>no credential proceeds anonymously (authorization is enforced per-resource downstream).</li>
 * </ul>
 *
 * <p><b>No Shiro (finding H20).</b> A valid credential used to build an Apache Shiro {@code Subject}
 * and call {@code login()} on it. Nothing ever read that subject back — there is no
 * {@code SecurityUtils.getSubject()}, {@code hasRole} or {@code isPermitted} anywhere in this server,
 * and authorization is decided by {@link com.ebremer.lws.server.core.Authorizer} from the resource
 * IRI and mode — but {@code login()} creates a native session with a 30-minute timeout in an
 * in-memory session DAO, once per authenticated request, and nothing ever logged out. Because
 * {@code did:key} credentials are self-issued and need no registration, anyone could mint an
 * unlimited stream of valid ones offline and pin hundreds of thousands of session objects in the
 * heap without a single request having to succeed. The realm, the token type and the dependency are
 * gone with it.
 *
 * @author Erich Bremer
 */
public final class AuthenticationFilter implements Filter {

    /** Request attribute under which the authenticated {@link LwsPrincipal} (if any) is stored. */
    public static final String PRINCIPAL_ATTR = "com.ebremer.lws.server.principal";

    private final LwsCredentialValidator validator;
    private final DpopValidator dpop;
    private final LwsConfiguration config;

    public AuthenticationFilter(LwsCredentialValidator validator, DpopValidator dpop,
            LwsConfiguration config) {
        this.validator = validator;
        this.dpop = dpop;
        this.config = config;
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
            // Kept from the Shiro realm this replaced, which refused a token whose subject was
            // absent. No validator produces such a principal today; a future one that did would
            // otherwise authenticate a request as nobody, and every owner and ACL comparison
            // downstream is against a WebID.
            if (principal.webId() == null) {
                unauthorized(response, "Bearer", "the credential names no subject");
                return;
            }
            request.setAttribute(PRINCIPAL_ATTR, principal);
            chain.doFilter(req, res);
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
            boolean bearer = scheme.equalsIgnoreCase("Bearer");
            // RFC 9449 §7.1: a DPoP-bound access token must never be honoured as a bearer token.
            // Checked before validation so a downgraded token cannot even drive the outbound
            // subject-document fetch that validation would perform.
            //
            // Applied to BOTH schemes, not just Bearer. `LwsCredentialValidator` routes by the
            // credential's *shape* — it parses the value as a JWT first and only falls back to SAML
            // on a parse failure — so while these were gated on `bearer` the word `SAML2` was an
            // unconditional alias for `Bearer` for every JWT, with both defences removed: a
            // captured `cnf.jkt` token was honoured with no proof, and `lws.dpop.require=true` was
            // bypassed by changing one word in the request. A genuine SAML assertion is base64 XML
            // and does not parse as a JWT, so `isSenderConstrained` is a no-op for it, and an
            // operator who required DPoP meant every scheme.
            if (config.dpopRequired()) {
                unauthorized(response, "DPoP", "this storage requires DPoP-bound access tokens");
                return null;
            }
            if (DpopValidator.isSenderConstrained(value)) {
                unauthorized(response, "DPoP",
                        "this access token is DPoP-bound and must be presented with the DPoP scheme and a proof");
                return null;
            }
            // And the scheme now has to agree with the credential. Announcing SAML2 and presenting a
            // JWT is not a request any real client makes; letting it through is what made the two
            // schemes interchangeable in the first place.
            if (!bearer && isJwt(value)) {
                unauthorized(response, "SAML2", "the SAML2 scheme carries a SAML assertion, not a JWT");
                return null;
            }
            Optional<LwsPrincipal> validated = validator.validate(value);
            if (validated.isEmpty()) {
                unauthorized(response, bearer ? "Bearer" : "SAML2", "invalid or expired credential");
                return null;
            }
            return validated.get();
        }
        return null; // unrecognized scheme -> anonymous
    }

    /**
     * Authenticate a DPoP-bound request: verify the proof, then the access token, then bind the two,
     * and only then consume the proof.
     *
     * <p>The order is the fix for finding M6. Everything up to and including {@code ath} can be
     * satisfied by an unauthenticated client on its own — the proof carries its own verification key,
     * and {@code ath} only has to match whatever string is presented as the access token — so
     * claiming the proof's {@code jti} at that point let anyone write an entry per request into the
     * bounded replay cache, and a full cache evicts unexpired entries, which re-enables replay.
     * {@link DpopValidator#claimProof} therefore runs last, after the access token has validated and
     * is confirmed bound to the proof key, so filling the cache costs what a real request costs.
     */
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
        if (!dpop.claimProof(proof)) {
            unauthorized(response, "DPoP", "this DPoP proof has already been used");
            return null;
        }
        return validated.get();
    }

    /** True if {@code credential} is a parseable JWS, i.e. a JWT rather than a SAML assertion. */
    private static boolean isJwt(String credential) {
        try {
            com.nimbusds.jwt.SignedJWT.parse(credential);
            return true;
        } catch (java.text.ParseException e) {
            return false;
        }
    }

    /** Challenge the client to repeat the request with a server-issued nonce (RFC 9449 §8). */
    private void dpopNonceChallenge(HttpServletResponse response) throws IOException {
        response.setHeader("DPoP-Nonce", dpop.issueNonce());
        response.setHeader("WWW-Authenticate", HttpSupport.challenge("DPoP", config, "use_dpop_nonce",
                "a nonce is required in the DPoP proof"));
        HttpSupport.addStorageLink(response, config);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "use_dpop_nonce");
    }

    /**
     * Refuse a presented credential with {@code 401}: an {@code invalid_token} challenge in the
     * lws10-core shape — naming the authorization server to get a token from, and the storage as
     * realm — and the link to the storage, so the client can recover without a hardcoded URI.
     */
    private void unauthorized(HttpServletResponse response, String scheme, String description)
            throws IOException {
        response.setHeader("WWW-Authenticate",
                HttpSupport.challenge(scheme, config, "invalid_token", description));
        HttpSupport.addStorageLink(response, config);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, description);
    }

    private static String path(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String ctx = request.getContextPath();
        String p = (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) ? uri.substring(ctx.length()) : uri;
        return p.isEmpty() ? "/" : p;
    }
}
