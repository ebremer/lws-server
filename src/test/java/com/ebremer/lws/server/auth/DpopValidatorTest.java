package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Tests DPoP (RFC 9449) proof verification and the {@code cnf.jkt} binding check.
 *
 * @author Erich Bremer
 */
class DpopValidatorTest {

    private static final String HTU = "https://lws.example/foo";
    private static final String ACCESS_TOKEN = "header.payload.signature";

    @Test
    void acceptsValidProofAndReturnsThumbprint() throws Exception {
        ECKey key = ecKey();
        String proof = proof(key, "POST", HTU, "jti-1", new Date(), ath(ACCESS_TOKEN));
        Optional<String> jkt = new DpopValidator().verifyProof("POST", HTU, proof, ACCESS_TOKEN);
        assertTrue(jkt.isPresent());
        assertEquals(key.computeThumbprint().toString(), jkt.get());
    }

    @Test
    void rejectsWrongMethodHtuType() throws Exception {
        ECKey key = ecKey();
        DpopValidator v = new DpopValidator();
        String good = proof(key, "POST", HTU, "m1", new Date(), ath(ACCESS_TOKEN));
        assertTrue(v.verifyProof("GET", HTU, good, ACCESS_TOKEN).isEmpty());            // wrong htm
        assertTrue(v.verifyProof("POST", HTU + "x", proof(key, "POST", HTU, "m2", new Date(), ath(ACCESS_TOKEN)),
                ACCESS_TOKEN).isEmpty());                                                // wrong htu
        String wrongType = proofWithType(key, "jwt", "POST", HTU, "m3", new Date(), ath(ACCESS_TOKEN));
        assertTrue(v.verifyProof("POST", HTU, wrongType, ACCESS_TOKEN).isEmpty());       // typ != dpop+jwt
    }

    @Test
    void rejectsWrongAthAndExpiredIat() throws Exception {
        ECKey key = ecKey();
        DpopValidator v = new DpopValidator();
        // ath computed for a different token
        String mismatched = proof(key, "POST", HTU, "a1", new Date(), ath("other-token"));
        assertTrue(v.verifyProof("POST", HTU, mismatched, ACCESS_TOKEN).isEmpty());
        // iat far in the past
        String expired = proof(key, "POST", HTU, "a2", new Date(System.currentTimeMillis() - 3_600_000L),
                ath(ACCESS_TOKEN));
        assertTrue(v.verifyProof("POST", HTU, expired, ACCESS_TOKEN).isEmpty());
    }

    @Test
    void rejectsReplayedJti() throws Exception {
        ECKey key = ecKey();
        DpopValidator v = new DpopValidator();
        String proof = proof(key, "POST", HTU, "replay-jti", new Date(), ath(ACCESS_TOKEN));
        assertTrue(v.verifyProof("POST", HTU, proof, ACCESS_TOKEN).isPresent()); // first use
        assertTrue(v.verifyProof("POST", HTU, proof, ACCESS_TOKEN).isEmpty());   // replay
    }

    @Test
    void nonceRequiredProofs() throws Exception {
        ECKey key = ecKey();
        DpopNonceService nonces = new DpopNonceService();
        DpopValidator v = new DpopValidator(nonces);
        assertTrue(v.nonceRequired());

        // A proof without a nonce claim is not nonce-valid (the filter would issue a challenge).
        String noNonce = proof(key, "POST", HTU, "n1", new Date(), ath(ACCESS_TOKEN));
        assertFalse(v.isNonceValid(noNonce));

        // A proof carrying a freshly issued nonce is nonce-valid, and the proof itself still verifies.
        String withNonce = proofWithNonce(key, "POST", HTU, "n2", new Date(), ath(ACCESS_TOKEN), nonces.issue());
        assertTrue(v.isNonceValid(withNonce));
        assertTrue(v.verifyProof("POST", HTU, withNonce, ACCESS_TOKEN).isPresent());

        // The default validator requires no nonce.
        assertFalse(new DpopValidator().nonceRequired());
        assertTrue(new DpopValidator().isNonceValid(noNonce));
    }

    @Test
    void confirmationBindingCheck() throws Exception {
        ECKey key = ecKey();
        String jkt = key.computeThumbprint().toString();
        assertTrue(DpopValidator.isBoundTo(accessTokenWithCnf(key, jkt), jkt));
        assertFalse(DpopValidator.isBoundTo(accessTokenWithCnf(key, null), jkt));        // no cnf
        assertFalse(DpopValidator.isBoundTo(accessTokenWithCnf(key, "different"), jkt)); // wrong jkt
    }

    // ----- helpers -----

    private static ECKey ecKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        return new ECKey.Builder(Curve.P_256, (ECPublicKey) kp.getPublic())
                .privateKey((ECPrivateKey) kp.getPrivate()).build();
    }

    private static String proof(ECKey key, String htm, String htu, String jti, Date iat, String ath)
            throws Exception {
        return proofWithType(key, "dpop+jwt", htm, htu, jti, iat, ath);
    }

    private static String proofWithType(ECKey key, String typ, String htm, String htu, String jti,
            Date iat, String ath) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(typ))
                .jwk(key.toPublicJWK())
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(jti).claim("htm", htm).claim("htu", htu).issueTime(iat).claim("ath", ath).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static String proofWithNonce(ECKey key, String htm, String htu, String jti, Date iat,
            String ath, String nonce) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK()).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().jwtID(jti).claim("htm", htm).claim("htu", htu)
                .issueTime(iat).claim("ath", ath).claim("nonce", nonce).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static String accessTokenWithCnf(ECKey key, String jkt) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().subject("https://alice.example/me");
        if (jkt != null) {
            claims.claim("cnf", Map.of("jkt", jkt));
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims.build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static String ath(String accessToken) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(accessToken.getBytes("US-ASCII"));
        return Base64URL.encode(digest).toString();
    }
}
