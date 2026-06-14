package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Optional;
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
    private final DocumentLoader resolver = url -> SUB.equals(url) ? cidDocument : null;
    private final SsiCidValidator validator = new SsiCidValidator(resolver);

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
        SsiCidValidator noDoc = new SsiCidValidator(url -> null);
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
}
