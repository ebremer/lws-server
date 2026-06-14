package com.ebremer.lws.server.auth;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Shared helpers for the authentication-suite tests: Ed25519 key generation and JWT signing,
 * done with BouncyCastle (no Tink) to mirror how the server verifies Ed25519.
 */
final class AuthTestSupport {

    private AuthTestSupport() {
    }

    record Ed(byte[] privateRaw, byte[] publicRaw) {
        OctetKeyPair publicJwk() {
            return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(publicRaw)).build();
        }
    }

    static Ed ed25519() {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        byte[] pub = ((Ed25519PublicKeyParameters) kp.getPublic()).getEncoded();
        byte[] priv = ((Ed25519PrivateKeyParameters) kp.getPrivate()).getEncoded();
        return new Ed(priv, pub);
    }

    static String didKeyEd25519(byte[] publicRaw) {
        byte[] data = new byte[publicRaw.length + 2];
        data[0] = (byte) 0xed;
        data[1] = 0x01;
        System.arraycopy(publicRaw, 0, data, 2, publicRaw.length);
        return "did:key:z" + Base58.encode(data);
    }

    static String signEdDSA(Ed key, String kid, String sub, String iss, String clientId, Date exp) {
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.EdDSA);
        if (kid != null) {
            header.keyID(kid);
        }
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().subject(sub).expirationTime(exp);
        if (iss != null) {
            claims.issuer(iss);
        }
        if (clientId != null) {
            claims.claim("client_id", clientId);
        }
        Base64URL h = header.build().toBase64URL();
        Base64URL p = new Payload(claims.build().toJSONObject()).toBase64URL();
        String signingInput = h.toString() + "." + p.toString();
        byte[] toSign = signingInput.getBytes(StandardCharsets.US_ASCII);

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, new Ed25519PrivateKeyParameters(key.privateRaw(), 0));
        signer.update(toSign, 0, toSign.length);
        byte[] signature = signer.generateSignature();

        return signingInput + "." + Base64URL.encode(signature);
    }

    static Date future() {
        return new Date(System.currentTimeMillis() + 3_600_000L);
    }

    static Date past() {
        return new Date(System.currentTimeMillis() - 3_600_000L);
    }
}
