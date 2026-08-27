package com.ebremer.lws.server.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.auth.AudiencePolicy;
import com.ebremer.lws.server.auth.DidKeyValidator;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Verifies the {@link DidKeyTool} produces a did:key and a token that the server's
 * {@link DidKeyValidator} accepts, and that reusing the seed yields the same DID.
 *
 * @author Erich Bremer
 */
class DidKeyToolTest {

    private static DidKeyValidator lenient() {
        return new DidKeyValidator(AudiencePolicy.permitAll(), 0);
    }

    @Test
    void mintsTokenAcceptedByValidator() {
        DidKeyTool.Minted minted = DidKeyTool.mint(null, 3600, null);
        assertTrue(minted.did().startsWith("did:key:z"));

        Optional<LwsPrincipal> principal = lenient().validate(minted.token());
        assertTrue(principal.isPresent(), "minted token should be accepted");
        assertEquals(minted.did(), principal.get().webId());

        // Re-minting with the same seed yields the same DID (stable owner identity).
        byte[] seed = Base64.getUrlDecoder().decode(minted.privateKeySeedBase64Url());
        DidKeyTool.Minted again = DidKeyTool.mint(seed, 3600, null);
        assertEquals(minted.did(), again.did());
        assertTrue(lenient().validate(again.token()).isPresent());
    }

    /**
     * A storage that requires an audience (the default) only accepts a token minted with
     * {@code --audience}, so the tool's flag is not optional in practice.
     */
    @Test
    void audienceFlagIsRequiredByAStorageThatBindsAudiences() {
        String storage = "https://storage.example";
        DidKeyValidator strict = new DidKeyValidator(new AudiencePolicy(Set.of(storage), true), 3_600_000L);

        assertTrue(strict.validate(DidKeyTool.mint(null, 3600, null).token()).isEmpty(),
                "a token minted without --audience is refused by an audience-binding storage");
        assertTrue(strict.validate(DidKeyTool.mint(null, 3600, storage).token()).isPresent(),
                "a token minted with --audience for this storage is accepted");
        assertTrue(strict.validate(DidKeyTool.mint(null, 3600, "https://other.example").token()).isEmpty(),
                "a token minted for another storage is refused");
    }
}
