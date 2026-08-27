package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Tests the {@code Authorization} scheme rules in {@link AuthenticationFilter}, in particular
 * RFC 9449 §7.1: a DPoP-bound ({@code cnf.jkt}-bearing) access token must not be honoured when it
 * is presented as a plain bearer token, because the whole point of the binding is that possession
 * of the token alone is insufficient.
 *
 * @author Erich Bremer
 */
class AuthenticationFilterTest {

    private static final String BASE = "http://localhost:8080";

    private final AuthTestSupport.Ed key = AuthTestSupport.ed25519();
    private final String did = AuthTestSupport.didKeyEd25519(key.publicRaw());

    private static LwsConfiguration config(boolean requireDpop) {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        // An owner, because this class asserts nothing about authorization and the
        // development posture now has to be asked for explicitly.
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        p.setProperty("lws.audience.require", "false"); // audience binding is exercised elsewhere
        if (requireDpop) {
            p.setProperty("lws.dpop.require", "true");
        }
        return LwsConfiguration.of(p);
    }

    private static AuthenticationFilter filter(LwsConfiguration config) {
        LwsCredentialValidator credentials = new LwsCredentialValidator(
                new LwsOpenIdValidator(OutboundFetchPolicy.permitAll(),
                        new HttpDocumentLoader(OutboundFetchPolicy.permitAll()), AudiencePolicy.permitAll()),
                new SsiCidValidator(url -> null, AudiencePolicy.permitAll(), 0),
                new DidKeyValidator(AudiencePolicy.permitAll(), 0), null);
        return new AuthenticationFilter(credentials, new DpopValidator(), config);
    }

    /** A response mock whose {@code isCommitted()} flips once an error has been sent, as a container's does. */
    private static HttpServletResponse committingResponse(AtomicBoolean committed) throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        doAnswer(invocation -> {
            committed.set(true);
            return null;
        }).when(response).sendError(anyInt(), anyString());
        when(response.isCommitted()).thenAnswer(invocation -> committed.get());
        return response;
    }

    private static HttpServletRequest requestWith(String authorization) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn(authorization);
        when(request.getRequestURI()).thenReturn("/doc");
        when(request.getContextPath()).thenReturn("");
        when(request.getMethod()).thenReturn("GET");
        return request;
    }

    @Test
    void refusesADpopBoundTokenPresentedAsBearer() throws Exception {
        String bound = AuthTestSupport.signEdDSAWithCnf(
                key, did, AuthTestSupport.future(), "some-key-thumbprint");

        AtomicBoolean committed = new AtomicBoolean();
        HttpServletResponse response = committingResponse(committed);
        FilterChain chain = mock(FilterChain.class);

        filter(config(false)).doFilter(requestWith("Bearer " + bound), response, chain);

        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
        verify(chain, never()).doFilter(any(), any());
    }

    /** The contrast: an ordinary, unbound token of the same shape is still accepted over Bearer. */
    @Test
    void acceptsAnUnboundTokenPresentedAsBearer() throws Exception {
        String unbound = AuthTestSupport.signEdDSA(key, null, did, did, did, AuthTestSupport.future());

        AtomicBoolean committed = new AtomicBoolean();
        HttpServletResponse response = committingResponse(committed);
        HttpServletRequest request = requestWith("Bearer " + unbound);
        FilterChain chain = mock(FilterChain.class);

        filter(config(false)).doFilter(request, response, chain);

        verify(response, never()).sendError(anyInt(), anyString());
        verify(chain).doFilter(request, response);
        verify(request).setAttribute(eq(AuthenticationFilter.PRINCIPAL_ATTR),
                argThat(value -> value instanceof LwsPrincipal p && did.equals(p.webId())));
    }

    @Test
    void refusesPlainBearerEntirelyWhenDpopIsRequired() throws Exception {
        String unbound = AuthTestSupport.signEdDSA(key, null, did, did, did, AuthTestSupport.future());

        AtomicBoolean committed = new AtomicBoolean();
        HttpServletResponse response = committingResponse(committed);
        FilterChain chain = mock(FilterChain.class);

        filter(config(true)).doFilter(requestWith("Bearer " + unbound), response, chain);

        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
        verify(chain, never()).doFilter(any(), any());
    }

    /**
     * The {@code SAML2} scheme gets the same two DPoP downgrade defences as {@code Bearer}.
     *
     * <p>Both guards used to be gated on {@code bearer &&}, while
     * {@link LwsCredentialValidator#validate} routes by the credential's <em>shape</em> — it parses
     * the value as a JWT first and reaches the SAML validator only when that fails. So the word
     * {@code SAML2} was an unconditional alias for {@code Bearer} for every JWT, with both defences
     * removed: a captured {@code cnf.jkt}-bound token was honoured with no proof, in flat
     * contradiction of RFC 9449 §7.1, and {@code lws.dpop.require=true} was bypassed by changing one
     * word in the request. Against that code both assertions here authenticate instead of refusing.
     */
    @Test
    void theSaml2SchemeIsNotAWayAroundTheDpopDefences() throws Exception {
        String bound = AuthTestSupport.signEdDSAWithCnf(
                key, did, AuthTestSupport.future(), "some-key-thumbprint");
        HttpServletResponse boundResponse = committingResponse(new AtomicBoolean());
        FilterChain boundChain = mock(FilterChain.class);
        filter(config(false)).doFilter(requestWith("SAML2 " + bound), boundResponse, boundChain);
        verify(boundResponse).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
        verify(boundChain, never()).doFilter(any(), any());

        // And an unbound token, which Bearer would accept, is refused under SAML2 when DPoP is
        // required — an operator who required DPoP meant every scheme.
        String unbound = AuthTestSupport.signEdDSA(key, null, did, did, did, AuthTestSupport.future());
        HttpServletResponse requiredResponse = committingResponse(new AtomicBoolean());
        FilterChain requiredChain = mock(FilterChain.class);
        filter(config(true)).doFilter(requestWith("SAML2 " + unbound), requiredResponse, requiredChain);
        verify(requiredResponse).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
        verify(requiredChain, never()).doFilter(any(), any());
    }

    /**
     * And the scheme has to agree with the credential: announcing {@code SAML2} while presenting a
     * JWT is refused outright, so the two schemes can no longer be used interchangeably at all.
     */
    @Test
    void aJwtPresentedUnderTheSaml2SchemeIsRefused() throws Exception {
        String unbound = AuthTestSupport.signEdDSA(key, null, did, did, did, AuthTestSupport.future());
        HttpServletResponse response = committingResponse(new AtomicBoolean());
        FilterChain chain = mock(FilterChain.class);

        filter(config(false)).doFilter(requestWith("SAML2 " + unbound), response, chain);

        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void detectsSenderConstraintOnTokensAndIgnoresNonJwtCredentials() {
        String bound = AuthTestSupport.signEdDSAWithCnf(
                key, did, AuthTestSupport.future(), "some-key-thumbprint");
        String unbound = AuthTestSupport.signEdDSA(key, null, did, did, did, AuthTestSupport.future());

        assertTrue(DpopValidator.isSenderConstrained(bound));
        assertFalse(DpopValidator.isSenderConstrained(unbound));
        assertFalse(DpopValidator.isSenderConstrained("not-a-jwt"));
    }
}
