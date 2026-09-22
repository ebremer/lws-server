package com.ebremer.lws.server.auth;

import com.nimbusds.jose.jwk.JWK;

/**
 * Parses a {@code did:key} identifier into its public verification key, per the did:key method:
 * the identifier is {@code did:key:<multibase>}, where the multibase value is a {@code Multikey} —
 * {@code z} + base58btc(multicodec header || raw public key).
 *
 * <p>Supports Ed25519 ({@code 0xed}), P-256 ({@code 0x1200}), P-384 ({@code 0x1201}) and secp256k1
 * ({@code 0xe7}); the decoding, and its refusal of non-canonical encodings and private keys, is
 * {@link Multikey}'s.
 *
 * @author Erich Bremer
 */
final class DidKey {

    private DidKey() {
    }

    static final String PREFIX = "did:key:";

    static JWK toPublicJwk(String did) {
        if (did == null || !did.startsWith(PREFIX)) {
            throw new IllegalArgumentException("not a did:key");
        }
        return Multikey.decode(did.substring(PREFIX.length())).jwk();
    }
}
