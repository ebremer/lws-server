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
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
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

    /**
     * Validate a self-signed credential's temporal claims: it must carry an {@code exp} that is
     * still in the future, must not be post-dated ({@code nbf}/{@code iat} in the future), and —
     * when {@code maxLifetimeMs} is positive — must not claim a lifetime longer than the server
     * allows.
     *
     * <p>The lifetime bound matters because these credentials are minted by the client itself:
     * without it a holder can issue a token valid for a century, so a single leak is a permanent,
     * unrevocable credential. The lifetime is measured from {@code iat} when present (the token's
     * own claim about how long it is meant to live) and from now otherwise.
     *
     * @param maxLifetimeMs the maximum accepted token lifetime, or {@code <= 0} for unlimited
     */
    static boolean temporalClaimsValid(JWTClaimsSet claims, long maxLifetimeMs) {
        long now = System.currentTimeMillis();
        Date exp = claims.getExpirationTime();
        if (exp == null || exp.getTime() <= now - CLOCK_SKEW_MS) {
            return false; // missing or expired
        }
        Date nbf = claims.getNotBeforeTime();
        if (nbf != null && nbf.getTime() > now + CLOCK_SKEW_MS) {
            return false; // not yet valid
        }
        Date iat = claims.getIssueTime();
        if (iat != null && iat.getTime() > now + CLOCK_SKEW_MS) {
            return false; // issued in the future
        }
        if (maxLifetimeMs > 0) {
            long basis = iat != null ? iat.getTime() : now;
            if (exp.getTime() - basis > maxLifetimeMs + CLOCK_SKEW_MS) {
                return false; // lifetime longer than this storage accepts
            }
        }
        return true;
    }

    /**
     * Verify a JWT's signature against a public JWK (RSA, EC or OKP/Ed25519).
     *
     * <p>The key's declared algorithm is cross-checked against the header, because "this JWK is an
     * OKP" is not the same statement as "this JWK is an Ed25519 signing key". {@link OctetKeyPair}
     * also covers <strong>X25519</strong>, which is a key-agreement key and cannot sign anything —
     * yet its {@code x} is 32 bytes, so feeding it to an Ed25519 verifier is a perfectly well-typed
     * way to check a signature against a key that was never meant to make one. A JWK also carries an
     * optional {@code use}/{@code key_ops}, and a key marked for encryption is likewise not a
     * signing key.
     */
    static boolean verify(SignedJWT jwt, JWK jwk) throws JOSEException {
        requireSigningKey(jwt, jwk);
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

    /** Refuse a key that cannot make the signature the header claims it made. */
    private static void requireSigningKey(SignedJWT jwt, JWK jwk) throws JOSEException {
        if (jwk.getKeyUse() != null && !KeyUse.SIGNATURE.equals(jwk.getKeyUse())) {
            throw new JOSEException("JWK is not a signing key (use=" + jwk.getKeyUse() + ")");
        }
        if (jwk.getKeyOperations() != null && !jwk.getKeyOperations().contains(KeyOperation.VERIFY)) {
            throw new JOSEException("JWK does not permit verification (key_ops=" + jwk.getKeyOperations() + ")");
        }
        JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
        if (jwk.getAlgorithm() != null && !jwk.getAlgorithm().equals(alg)) {
            throw new JOSEException("JWS alg " + alg + " does not match the JWK's declared alg "
                    + jwk.getAlgorithm());
        }
        if (jwk instanceof OctetKeyPair okp) {
            if (!JWSAlgorithm.EdDSA.equals(alg)) {
                throw new JOSEException("An OKP key cannot verify a " + alg + " signature");
            }
            if (!Curve.Ed25519.equals(okp.getCurve())) {
                // X25519 is key agreement, not signing; its x is also 32 bytes, so nothing further
                // down would have noticed.
                throw new JOSEException("OKP curve " + okp.getCurve() + " cannot sign; expected Ed25519");
            }
        } else if (JWSAlgorithm.EdDSA.equals(alg)) {
            throw new JOSEException("EdDSA requires an OKP key, not " + jwk.getKeyType());
        }
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
