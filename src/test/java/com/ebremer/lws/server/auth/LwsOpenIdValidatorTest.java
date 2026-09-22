package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
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
 * <p>Two refusals that look identical from the outside are pinned separately (finding M44): a token
 * whose {@code kid} names no key in the JWKS is rejected by key selection and never reaches a
 * verifier, while a token carrying the provider's own {@code kid} over a foreign key pair is
 * rejected by the signature check itself. Only the second exercises the cryptography.
 *
 * @author Erich Bremer
 */
class LwsOpenIdValidatorTest {

    private static MockOidcProvider idp;
    // permitAll: the mock IdP runs on loopback, which the default policy would block.
    private static final OutboundFetchPolicy PERMIT_ALL = OutboundFetchPolicy.permitAll();
    private static final AudiencePolicy AUDIENCE =
            new AudiencePolicy(Set.of(MockOidcProvider.DEFAULT_AUDIENCE), true);

    private final LwsOpenIdValidator validator =
            new LwsOpenIdValidator(PERMIT_ALL, new HttpDocumentLoader(PERMIT_ALL), AUDIENCE);

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

    /**
     * The subject document as lws10-authn-openid's own example writes it — plain JSON with the CID v1
     * context, served as {@code application/json} — establishes trust; the RDF reading this server
     * relied on could not parse it (no JSON-LD media type, and a context it refused to fetch).
     */
    @Test
    void acceptsTheSuitesOwnJsonCidDocument() throws Exception {
        String token = idp.mintIdToken(idp.jsonCidSubject(), Instant.now().plusSeconds(3600));
        Optional<LwsPrincipal> principal = validator.validate(token);
        assertTrue(principal.isPresent(), "the JSON CID document names this issuer");
        assertEquals(idp.jsonCidSubject(), principal.get().webId());

        String other = idp.mintIdToken(idp.jsonCidSubjectOfAnotherProvider(), Instant.now().plusSeconds(3600));
        assertTrue(validator.validate(other).isEmpty(), "a document naming another provider does not");
    }

    @Test
    void rejectsSubjectThatDoesNotTrustIssuer() throws Exception {
        String token = idp.mintIdToken(idp.untrustedSubject(), Instant.now().plusSeconds(3600));
        assertTrue(validator.validate(token).isEmpty(),
                "subject whose CID doc lacks the OpenIdProvider service must be rejected");
    }

    /**
     * Finding M3. The trust query used to leave the service node unbound, so it asked only whether
     * the fetched graph mentioned <em>any</em> {@code lws:OpenIdProvider} pointing at the issuer.
     * A profile that merely describes a neighbour — a {@code foaf:knows}, an aggregator page, a
     * shared document — would then hand its neighbour's trust to a subject that claims nothing.
     */
    @Test
    void rejectsSubjectWhoseDocumentNamesTheProviderOnlyForSomeoneElse() throws Exception {
        String token = idp.mintIdToken(idp.neighbourTrustedSubject(), Instant.now().plusSeconds(3600));
        assertTrue(validator.validate(token).isEmpty(),
                "the provider link must start at the subject, not at a neighbour it describes");
        // The control: that neighbour really is trusted, so the document genuinely does contain a
        // matching service — anchoring the query to the subject is the whole difference.
        assertTrue(validator.validate(
                idp.mintIdToken(idp.trustedSubject(), Instant.now().plusSeconds(3600))).isPresent());
    }

    /** The trust step on its own, as the interactive browser login uses it (finding M12). */
    @Test
    void exposesTheTrustStepForACallerThatAlreadyHasAValidatedToken() {
        assertTrue(validator.trusts(idp.trustedSubject(), idp.issuer()));
        assertTrue(validator.trusts(idp.cidTrustedSubject(), idp.issuer()));
        assertFalse(validator.trusts(idp.untrustedSubject(), idp.issuer()));
        assertFalse(validator.trusts(idp.neighbourTrustedSubject(), idp.issuer()));
        assertFalse(validator.trusts(idp.trustedSubject(), "https://some-other-issuer.example"));
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        String token = idp.mintIdToken(idp.trustedSubject(), Instant.now().minusSeconds(60));
        assertTrue(validator.validate(token).isEmpty(), "expired token must be rejected");
    }

    /**
     * A genuinely forged signature, not merely a key the selector cannot find.
     *
     * <p>Finding M44. This case used to mint with {@code keyID("foreign")}: the JWKS holds exactly
     * one key, {@code test-key}, so Nimbus's {@code JWSVerificationKeySelector} selected no
     * candidate and the token was refused before {@code RSASSAVerifier} ever ran — the
     * signature-verification path the test name claims to cover was never entered. Reusing the
     * provider's own {@code kid} over a different key pair means the selector does find a
     * candidate, so the rejection has to come from the cryptography.
     */
    @Test
    void rejectsTokenSignedByKeyNotInJwks() throws Exception {
        // The provider's kid ("test-key", see MockOidcProvider), over a key the provider never had.
        RSAKey foreign = new RSAKeyGenerator(2048).keyID("test-key").generate();
        String token = idp.mintIdToken(idp.trustedSubject(), Instant.now().plusSeconds(3600), foreign);
        assertTrue(validator.validate(token).isEmpty(),
                "a signature made by a key the JWKS does not hold must be rejected");
        // The control: same subject, same audience, same kid, the provider's real key -> accepted.
        // Without it this test would also pass if the selector had stopped finding the key at all.
        assertTrue(validator.validate(idp.mintIdToken(idp.trustedSubject(),
                Instant.now().plusSeconds(3600), idp.signingKeyForTests())).isPresent(),
                "the honest token must still be accepted");
    }

    /**
     * The other half of the same refusal, pinned separately because from the outside the two look
     * identical: a {@code kid} naming no key in the JWKS is rejected by key selection, before any
     * verifier runs. Both must stay refused, and conflating them is what hid the gap above.
     */
    @Test
    void rejectsTokenWhoseKidNamesNoKeyInTheJwks() throws Exception {
        RSAKey foreign = new RSAKeyGenerator(2048).keyID("foreign").generate();
        String token = idp.mintIdToken(idp.trustedSubject(), Instant.now().plusSeconds(3600), foreign);
        assertTrue(validator.validate(token).isEmpty(),
                "a token whose kid matches nothing in the JWKS must be rejected");
    }

    /**
     * The cross-relying-party replay this storage must refuse: the provider is the same, the
     * subject is the same, the signature is genuine — but the token was minted for a different
     * client, so it was never addressed to this storage.
     */
    @Test
    void rejectsTokenMintedForAnotherRelyingParty() throws Exception {
        String token = idp.mintIdToken(idp.trustedSubject(), Instant.now().plusSeconds(3600),
                idp.signingKeyForTests(), "some-other-relying-party");
        assertTrue(validator.validate(token).isEmpty(),
                "an ID token whose aud names a different relying party must be rejected");
    }

    @Test
    void rejectsTokenWithNoAudienceWhenAudienceIsRequired() throws Exception {
        String token = idp.mintIdToken(idp.trustedSubject(), Instant.now().plusSeconds(3600),
                idp.signingKeyForTests(), null);
        assertTrue(validator.validate(token).isEmpty(),
                "a token with no aud must be rejected when lws.audience.require is set");
    }

    @Test
    void acceptsTokenWithNoAudienceWhenAudienceIsNotRequired() throws Exception {
        LwsOpenIdValidator lenient = new LwsOpenIdValidator(PERMIT_ALL, new HttpDocumentLoader(PERMIT_ALL),
                new AudiencePolicy(Set.of(MockOidcProvider.DEFAULT_AUDIENCE), false));
        String token = idp.mintIdToken(idp.trustedSubject(), Instant.now().plusSeconds(3600),
                idp.signingKeyForTests(), null);
        assertTrue(lenient.validate(token).isPresent(),
                "an absent aud is tolerated when the requirement is switched off");

        String wrong = idp.mintIdToken(idp.trustedSubject(), Instant.now().plusSeconds(3600),
                idp.signingKeyForTests(), "some-other-relying-party");
        assertTrue(lenient.validate(wrong).isEmpty(),
                "a present-but-wrong aud is refused even when aud is not required");
    }
}
