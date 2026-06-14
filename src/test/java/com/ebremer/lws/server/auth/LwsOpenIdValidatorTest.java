package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.time.Instant;
import java.util.Optional;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Tests for the OpenID Connect credential suite against an in-process {@link MockOidcProvider}:
 * a valid ID token from a trusting subject is accepted; untrusted-subject, expired, and forged
 * tokens are rejected.
 *
 * @author Erich Bremer
 */
class LwsOpenIdValidatorTest {

    private static MockOidcProvider idp;
    // permitAll: the mock IdP runs on loopback, which the default policy would block.
    private final LwsOpenIdValidator validator = new LwsOpenIdValidator(OutboundFetchPolicy.permitAll());

    @BeforeAll
    static void start() throws Exception {
        idp = new MockOidcProvider();
    }

    @AfterAll
    static void stop() {
        if (idp != null) {
            idp.close();
        }
    }

    @Test
    void acceptsValidIdTokenFromTrustingSubject() throws Exception {
        String token = idp.mintIdToken(idp.trustedSubject(), Instant.now().plusSeconds(3600));
        Optional<LwsPrincipal> principal = validator.validate(token);
        assertTrue(principal.isPresent(), "a valid ID token should be accepted");
        assertEquals(idp.trustedSubject(), principal.get().webId());
        assertEquals(idp.issuer(), principal.get().issuer());
        assertEquals("lws-client", principal.get().clientId());
    }

    @Test
    void acceptsSubjectWhoseDocumentUsesTheCidShape() throws Exception {
        String token = idp.mintIdToken(idp.cidTrustedSubject(), Instant.now().plusSeconds(3600));
        Optional<LwsPrincipal> principal = validator.validate(token);
        assertTrue(principal.isPresent(),
                "a CID-v1-shaped document (did:serviceEndpoint) should establish trust");
        assertEquals(idp.cidTrustedSubject(), principal.get().webId());
    }

    @Test
    void rejectsSubjectThatDoesNotTrustIssuer() throws Exception {
        String token = idp.mintIdToken(idp.untrustedSubject(), Instant.now().plusSeconds(3600));
        assertTrue(validator.validate(token).isEmpty(),
                "subject whose CID doc lacks the OpenIdProvider service must be rejected");
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        String token = idp.mintIdToken(idp.trustedSubject(), Instant.now().minusSeconds(60));
        assertTrue(validator.validate(token).isEmpty(), "expired token must be rejected");
    }

    @Test
    void rejectsTokenSignedByKeyNotInJwks() throws Exception {
        RSAKey foreign = new RSAKeyGenerator(2048).keyID("foreign").generate();
        String token = idp.mintIdToken(idp.trustedSubject(), Instant.now().plusSeconds(3600), foreign);
        assertTrue(validator.validate(token).isEmpty(), "forged signature must be rejected");
    }
}
