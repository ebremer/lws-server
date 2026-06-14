package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Optional;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.junit.jupiter.api.Test;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Tests the did:key authentication suite: Ed25519 and P-256 credentials, plus rejection of
 * expired tokens, mismatched sub/iss, and bad signatures.
 *
 * @author Erich Bremer
 */
class DidKeyValidatorTest {

    private final DidKeyValidator validator = new DidKeyValidator();

    @Test
    void acceptsValidEd25519Credential() throws Exception {
        AuthTestSupport.Ed key = AuthTestSupport.ed25519();
        String did = AuthTestSupport.didKeyEd25519(key.publicRaw());

        String token = AuthTestSupport.signEdDSA(key, null, did, did, did, AuthTestSupport.future());
        Optional<LwsPrincipal> principal = validator.validate(token);
        assertTrue(principal.isPresent());
        assertEquals(did, principal.get().webId());
    }

    @Test
    void rejectsExpiredMismatchedAndForgedEd25519() throws Exception {
        AuthTestSupport.Ed key = AuthTestSupport.ed25519();
        String did = AuthTestSupport.didKeyEd25519(key.publicRaw());

        // expired
        assertTrue(validator.validate(
                AuthTestSupport.signEdDSA(key, null, did, did, did, AuthTestSupport.past())).isEmpty());
        // iss != sub
        assertTrue(validator.validate(
                AuthTestSupport.signEdDSA(key, null, did, did + "x", did, AuthTestSupport.future()))
                .isEmpty());
        // signed by a different key but claiming this did
        AuthTestSupport.Ed forger = AuthTestSupport.ed25519();
        assertTrue(validator.validate(
                AuthTestSupport.signEdDSA(forger, null, did, did, did, AuthTestSupport.future()))
                .isEmpty());
    }

    @Test
    void acceptsValidP256Credential() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();

        ECNamedCurveParameterSpec bc = ECNamedCurveTable.getParameterSpec("secp256r1");
        org.bouncycastle.math.ec.ECPoint point =
                bc.getCurve().createPoint(pub.getW().getAffineX(), pub.getW().getAffineY());
        byte[] compressed = point.getEncoded(true); // 33-byte SEC1 compressed point
        byte[] data = new byte[compressed.length + 2];
        data[0] = (byte) 0x80;
        data[1] = (byte) 0x24; // multicodec p256-pub varint
        System.arraycopy(compressed, 0, data, 2, compressed.length);
        String did = "did:key:z" + Base58.encode(data);

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256),
                new JWTClaimsSet.Builder().subject(did).issuer(did).claim("client_id", did)
                        .expirationTime(AuthTestSupport.future()).build());
        jwt.sign(new ECDSASigner(priv));

        // sanity: the key we built should match what DidKey parses
        ECKey parsed = (ECKey) DidKey.toPublicJwk(did);
        assertEquals(Curve.P_256, parsed.getCurve());

        Optional<LwsPrincipal> principal = validator.validate(jwt.serialize());
        assertTrue(principal.isPresent());
        assertEquals(did, principal.get().webId());
    }
}
