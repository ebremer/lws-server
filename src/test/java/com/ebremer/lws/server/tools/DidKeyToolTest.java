package com.ebremer.lws.server.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Base64;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.auth.DidKeyValidator;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Verifies the {@link DidKeyTool} produces a did:key and a token that the server's
 * {@link DidKeyValidator} accepts, and that reusing the seed yields the same DID.
 *
 * @author Erich Bremer
 */
class DidKeyToolTest {

    @Test
    void mintsTokenAcceptedByValidator() {
        DidKeyTool.Minted minted = DidKeyTool.mint(null, 3600, null);
        assertTrue(minted.did().startsWith("did:key:z"));

        Optional<LwsPrincipal> principal = new DidKeyValidator().validate(minted.token());
        assertTrue(principal.isPresent(), "minted token should be accepted");
        assertEquals(minted.did(), principal.get().webId());

        // Re-minting with the same seed yields the same DID (stable owner identity).
        byte[] seed = Base64.getUrlDecoder().decode(minted.privateKeySeedBase64Url());
        DidKeyTool.Minted again = DidKeyTool.mint(seed, 3600, null);
        assertEquals(minted.did(), again.did());
        assertTrue(new DidKeyValidator().validate(again.token()).isPresent());
    }
}
