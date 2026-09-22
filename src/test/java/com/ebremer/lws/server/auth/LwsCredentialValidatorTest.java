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
                + "\",\"type\":\"JsonWebKey\",\"controller\":\"" + sub
                + "\",\"publicKeyJwk\":" + key.publicJwk().toJSONString() + "}],"
                + "\"authentication\":[\"" + kid + "\"]}";
        DocumentLoader loader = url -> sub.equals(url) ? cidDoc : null;

        OutboundFetchPolicy permitAll = OutboundFetchPolicy.permitAll();
        AudiencePolicy anyAudience = AudiencePolicy.permitAll();
        LwsCredentialValidator orchestrator = new LwsCredentialValidator(
                new LwsOpenIdValidator(permitAll, new HttpDocumentLoader(permitAll), anyAudience),
                new SsiCidValidator(loader, anyAudience, 0),
                new DidKeyValidator(anyAudience, 0), null);

        // did:key shape with no kid -> the discontinued did:key suite, kept for such credentials
        String didToken = AuthTestSupport.signEdDSA(key, null, did, did, did, AuthTestSupport.future());
        assertEquals(did, orchestrator.validate(didToken).orElseThrow().webId());

        // did:key subject with a kid -> the SSI-CID suite, which now covers DID subjects
        String didKid = did + "#" + did.substring("did:key:".length());
        String didCidToken = AuthTestSupport.signEdDSA(key, didKid, did, did, did, AuthTestSupport.future());
        assertEquals(did, orchestrator.validate(didCidToken).orElseThrow().webId());

        // self-issued (iss == sub, http subject) -> SSI-CID suite
        String cidToken = AuthTestSupport.signEdDSA(key, kid, sub, sub, sub, AuthTestSupport.future());
        assertEquals(sub, orchestrator.validate(cidToken).orElseThrow().webId());

        // junk credential -> nothing
        assertTrue(orchestrator.validate("not-a-credential").isEmpty());
    }
}
