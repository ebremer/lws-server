package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Tests the Self-signed Controlled Identifier suite: a JWT verified against a publicKeyJwk found
 * (by {@code kid}) in the dereferenced controlled identifier document.
 *
 * @author Erich Bremer
 */
class SsiCidValidatorTest {

    private static final String SUB = "https://alice.example/cid";
    private static final String KID = SUB + "#key-1";

    private final AuthTestSupport.Ed key = AuthTestSupport.ed25519();
    private final String cidDocument = "{\"id\":\"" + SUB + "\","
            + "\"verificationMethod\":[{\"id\":\"" + KID + "\",\"type\":\"JsonWebKey2020\","
            + "\"controller\":\"" + SUB + "\",\"publicKeyJwk\":" + key.publicJwk().toJSONString()
            + "}]}";
    private static final String STORAGE = "https://storage.example";

    private final DocumentLoader resolver = url -> SUB.equals(url) ? cidDocument : null;
    private final SsiCidValidator validator =
            new SsiCidValidator(resolver, AudiencePolicy.permitAll(), 0);
    /** A storage that binds credentials to itself and caps self-minted token lifetimes at an hour. */
    private final SsiCidValidator strict =
            new SsiCidValidator(resolver, new AudiencePolicy(Set.of(STORAGE), true), 3_600_000L);

    @Test
    void acceptsValidSelfIssuedCredential() throws Exception {
        String token = AuthTestSupport.signEdDSA(key,KID, SUB, SUB, SUB, AuthTestSupport.future());
        Optional<LwsPrincipal> principal = validator.validate(token);
        assertTrue(principal.isPresent());
        assertEquals(SUB, principal.get().webId());
    }

    @Test
    void rejectsUnknownKidMissingDocExpiredAndForged() throws Exception {
        // kid not present in the CID document
        assertTrue(validator.validate(
                AuthTestSupport.signEdDSA(key,SUB + "#other", SUB, SUB, SUB, AuthTestSupport.future()))
                .isEmpty());
        // document cannot be dereferenced
        SsiCidValidator noDoc = new SsiCidValidator(url -> null, AudiencePolicy.permitAll(), 0);
        assertTrue(noDoc.validate(
                AuthTestSupport.signEdDSA(key,KID, SUB, SUB, SUB, AuthTestSupport.future())).isEmpty());
        // expired
        assertTrue(validator.validate(
                AuthTestSupport.signEdDSA(key,KID, SUB, SUB, SUB, AuthTestSupport.past())).isEmpty());
        // forged: signed by a different key but claiming the same subject/kid
        AuthTestSupport.Ed forger = AuthTestSupport.ed25519();
        assertTrue(validator.validate(
                AuthTestSupport.signEdDSA(forger, KID, SUB, SUB, SUB, AuthTestSupport.future()))
                .isEmpty());
    }

    /**
     * A self-signed credential is minted by its holder, so nothing but the {@code aud} claim ties
     * it to one storage. Without the check, the token a user presents to storage A is replayable
     * verbatim against storage B.
     */
    @Test
    void rejectsCredentialAddressedToAnotherStorage() throws Exception {
        String forOther = AuthTestSupport.signEdDSA(
                key, KID, SUB, SUB, SUB, AuthTestSupport.future(), "https://other-storage.example");
        assertTrue(strict.validate(forOther).isEmpty(),
                "a credential whose aud names another storage must be rejected");

        String forUs = AuthTestSupport.signEdDSA(
                key, KID, SUB, SUB, SUB, AuthTestSupport.future(), STORAGE);
        assertTrue(strict.validate(forUs).isPresent(), "a credential addressed to this storage is accepted");
    }

    @Test
    void rejectsCredentialWithNoAudienceWhenRequired() throws Exception {
        String noAud = AuthTestSupport.signEdDSA(key, KID, SUB, SUB, SUB, AuthTestSupport.future());
        assertTrue(strict.validate(noAud).isEmpty(),
                "a credential with no aud must be rejected when one is required");
    }

    /** An unbounded expiry turns a single leak into a permanent, unrevocable credential. */
    @Test
    void rejectsCredentialClaimingACenturyOfValidity() throws Exception {
        String forever = AuthTestSupport.signEdDSA(
                key, KID, SUB, SUB, SUB, AuthTestSupport.farFuture(), STORAGE);
        assertTrue(strict.validate(forever).isEmpty(),
                "a self-minted token claiming a 100-year lifetime must be rejected");
    }
}
