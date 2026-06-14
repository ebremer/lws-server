package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * Tests that the credential orchestrator routes each credential shape to the correct suite.
 *
 * @author Erich Bremer
 */
class LwsCredentialValidatorTest {

    @Test
    void routesDidKeyAndSsiCidCredentials() throws Exception {
        AuthTestSupport.Ed key = AuthTestSupport.ed25519();
        String did = AuthTestSupport.didKeyEd25519(key.publicRaw());

        String sub = "https://bob.example/cid";
        String kid = sub + "#k1";
        String cidDoc = "{\"id\":\"" + sub + "\",\"verificationMethod\":[{\"id\":\"" + kid
                + "\",\"publicKeyJwk\":" + key.publicJwk().toJSONString() + "}]}";
        DocumentLoader loader = url -> sub.equals(url) ? cidDoc : null;

        LwsCredentialValidator orchestrator = new LwsCredentialValidator(
                new LwsOpenIdValidator(OutboundFetchPolicy.permitAll()),
                new SsiCidValidator(loader), new DidKeyValidator(), null);

        // did:key shape -> did:key suite
        String didToken = AuthTestSupport.signEdDSA(key, null, did, did, did, AuthTestSupport.future());
        assertEquals(did, orchestrator.validate(didToken).orElseThrow().webId());

        // self-issued (iss == sub, http subject) -> SSI-CID suite
        String cidToken = AuthTestSupport.signEdDSA(key, kid, sub, sub, sub, AuthTestSupport.future());
        assertEquals(sub, orchestrator.validate(cidToken).orElseThrow().webId());

        // junk credential -> nothing
        assertTrue(orchestrator.validate("not-a-credential").isEmpty());
    }
}
