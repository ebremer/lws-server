package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * Tests the stateless HMAC DPoP nonce service: a freshly issued nonce validates; a tampered,
 * garbage, expired, or foreign-secret nonce does not.
 *
 * @author Erich Bremer
 */
class DpopNonceServiceTest {

    @Test
    void issuesAndValidatesNonces() {
        DpopNonceService service = new DpopNonceService();
        String nonce = service.issue();
        assertTrue(service.isValid(nonce));

        // Tampering with the payload invalidates it. Mutate the FIRST base64url character (all six
        // bits significant) rather than the last (whose low bits are unused padding and can decode to
        // the same bytes), so the decoded payload — and thus the MAC check — always differs.
        assertFalse(service.isValid((nonce.charAt(0) == 'A' ? "B" : "A") + nonce.substring(1)));
        assertFalse(service.isValid("garbage"));
        assertFalse(service.isValid(null));

        // A nonce minted by a different instance (different secret) is rejected.
        assertFalse(service.isValid(new DpopNonceService().issue()));
    }

    @Test
    void expiredNoncesAreRejected() throws Exception {
        DpopNonceService service = new DpopNonceService(1L, 0L); // 1 ms TTL, no skew
        String nonce = service.issue();
        Thread.sleep(20);
        assertFalse(service.isValid(nonce));
    }
}
