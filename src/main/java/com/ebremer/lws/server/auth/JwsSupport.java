package com.ebremer.lws.server.auth;

import java.text.ParseException;
import java.util.Date;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Shared JOSE helpers for the JWT-based authentication suites (OpenID, SSI-CID, did:key).
 *
 * <p>RSA and EC signatures are verified with Nimbus; Ed25519 (EdDSA) is verified with
 * BouncyCastle directly to avoid pulling in Google Tink (which Nimbus's Ed25519 support requires).
 *
 * @author Erich Bremer
 */
final class JwsSupport {

    private JwsSupport() {
    }

    static final long CLOCK_SKEW_MS = 60_000L;

    /** True if the JWT is signed with a real algorithm (rejects {@code alg: none}). */
    static boolean algNotNone(SignedJWT jwt) {
        JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
        return alg != null && !"none".equalsIgnoreCase(alg.getName());
    }

    /** True if the token has an expiry that is still in the future (allowing for clock skew). */
    static boolean notExpired(JWTClaimsSet claims) {
        Date exp = claims.getExpirationTime();
        return exp != null && exp.getTime() > System.currentTimeMillis() - CLOCK_SKEW_MS;
    }

    /** Verify a JWT's signature against a public JWK (RSA, EC or OKP/Ed25519). */
    static boolean verify(SignedJWT jwt, JWK jwk) throws JOSEException {
        if (jwk instanceof RSAKey rsa) {
            return jwt.verify(new RSASSAVerifier(rsa.toRSAPublicKey()));
        }
        if (jwk instanceof ECKey ec) {
            return jwt.verify(new ECDSAVerifier(ec.toECPublicKey()));
        }
        if (jwk instanceof OctetKeyPair okp) {
            return verifyEd25519(jwt, okp.getX().decode());
        }
        throw new JOSEException("Unsupported JWK key type: " + jwk.getKeyType());
    }

    private static boolean verifyEd25519(SignedJWT jwt, byte[] rawPublicKey) {
        byte[] signingInput = jwt.getSigningInput();
        byte[] signature = jwt.getSignature().decode();
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, new Ed25519PublicKeyParameters(rawPublicKey, 0));
        verifier.update(signingInput, 0, signingInput.length);
        return verifier.verifySignature(signature);
    }

    /** The LWS client identifier claim ({@code client_id}, falling back to {@code azp}). */
    static String clientId(JWTClaimsSet claims) throws ParseException {
        String clientId = claims.getStringClaim("client_id");
        return clientId != null ? clientId : claims.getStringClaim("azp");
    }
}
