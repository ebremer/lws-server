package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import jakarta.json.JsonObject;
import org.junit.jupiter.api.Test;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;

/**
 * DID subjects for the self-signed controlled identifier suite: DID syntax, the did:key document,
 * the did:web URL, and Multikey decoding — including what is refused rather than decoded.
 *
 * @author Erich Bremer
 */
class DidsAndMultikeyTest {

    @Test
    void didWebUrlsFollowTheMethodsReadOperation() {
        assertEquals("https://w3c-ccg.github.io/.well-known/did.json", Dids.didWebUrl("did:web:w3c-ccg.github.io"));
        assertEquals("https://w3c-ccg.github.io/user/alice/did.json",
                Dids.didWebUrl("did:web:w3c-ccg.github.io:user:alice"));
        assertEquals("https://example.com:3000/user/alice/did.json",
                Dids.didWebUrl("did:web:example.com%3A3000:user:alice"));
    }

    @Test
    void didWebRefusesWhatIsNotADomainName() {
        assertThrows(IllegalArgumentException.class, () -> Dids.didWebUrl("did:web:192.168.0.1"));
        assertThrows(IllegalArgumentException.class, () -> Dids.didWebUrl("did:web:-bad-.example"));
        assertThrows(IllegalArgumentException.class, () -> Dids.didWebUrl("did:web:example.com%3A99999"));
        assertThrows(IllegalArgumentException.class, () -> Dids.didWebUrl("did:web:example.com::x"));
        assertThrows(IllegalArgumentException.class, () -> Dids.didWebUrl("did:key:z6Mk"));
    }

    @Test
    void didSyntaxIsChecked() {
        assertEquals("web", Dids.methodOf("did:web:example.com"));
        assertEquals("example", Dids.methodOf("did:example:123:abc"));
        assertThrows(IllegalArgumentException.class, () -> Dids.methodOf("did:Web:example.com"));
        assertThrows(IllegalArgumentException.class, () -> Dids.methodOf("did:web:example.com/path"));
        assertThrows(IllegalArgumentException.class, () -> Dids.methodOf("did:web:example.com#frag"));
        assertThrows(IllegalArgumentException.class, () -> Dids.methodOf("https://example.com"));
    }

    @Test
    void aDidKeyExpandsToADocumentWithOneAuthenticationMethod() {
        AuthTestSupport.Ed key = AuthTestSupport.ed25519();
        String did = AuthTestSupport.didKeyEd25519(key.publicRaw());
        String multibase = did.substring("did:key:".length());
        JsonObject doc = Dids.didKeyDocument(did);
        assertEquals(did, doc.getString("id"));
        JsonObject method = doc.getJsonArray("verificationMethod").getJsonObject(0);
        assertEquals(did + "#" + multibase, method.getString("id"));
        assertEquals("Multikey", method.getString("type"));
        assertEquals(did, method.getString("controller"));
        assertEquals(multibase, method.getString("publicKeyMultibase"));
        assertEquals(did + "#" + multibase, doc.getJsonArray("authentication").getString(0));
    }

    @Test
    void multikeyDecodesEd25519() {
        AuthTestSupport.Ed key = AuthTestSupport.ed25519();
        String multibase = AuthTestSupport.didKeyEd25519(key.publicRaw()).substring("did:key:".length());
        Multikey.Decoded decoded = Multikey.decode(multibase);
        assertEquals(JWSAlgorithm.EdDSA, decoded.algorithm());
        assertEquals(key.publicJwk().getX(), ((OctetKeyPair) decoded.jwk()).getX());
    }

    @Test
    void multikeyDecodesACompressedP256Point() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        byte[] x = unsigned(pub.getW().getAffineX().toByteArray(), 32);
        byte[] compressed = new byte[35];
        compressed[0] = (byte) 0x80; // varint 0x1200 (p256-pub)
        compressed[1] = 0x24;
        compressed[2] = (byte) (pub.getW().getAffineY().testBit(0) ? 0x03 : 0x02);
        System.arraycopy(x, 0, compressed, 3, 32);
        Multikey.Decoded decoded = Multikey.decode("z" + Base58.encode(compressed));
        assertEquals(JWSAlgorithm.ES256, decoded.algorithm());
        ECKey ec = (ECKey) decoded.jwk();
        assertEquals(Curve.P_256, ec.getCurve());
        assertEquals(new ECKey.Builder(Curve.P_256, pub).build().getY(), ec.getY(), "the point decompresses");
    }

    @Test
    void multikeyRefusesPrivateKeysOtherEncodingsAndUnknownTypes() {
        AuthTestSupport.Ed key = AuthTestSupport.ed25519();
        byte[] secret = new byte[34];
        secret[0] = (byte) 0x80; // varint 0x1300 (ed25519-priv)
        secret[1] = 0x26;
        System.arraycopy(key.privateRaw(), 0, secret, 2, 32);
        IllegalArgumentException leaked = assertThrows(IllegalArgumentException.class,
                () -> Multikey.decode("z" + Base58.encode(secret)));
        assertTrue(leaked.getMessage().contains("PRIVATE"), leaked.getMessage());

        String multibase = AuthTestSupport.didKeyEd25519(key.publicRaw()).substring("did:key:".length());
        assertThrows(IllegalArgumentException.class, () -> Multikey.decode("z1" + multibase.substring(1)),
                "a leading zero byte moves the header: not a key type");
        assertThrows(IllegalArgumentException.class, () -> Multikey.decode("z0OIl"),
                "characters base58btc does not have");
        assertThrows(IllegalArgumentException.class, () -> Multikey.decode("u" + multibase.substring(1)),
                "only base58btc");
        byte[] unknown = {0x12, 0x20, 1, 2, 3};
        assertThrows(IllegalArgumentException.class, () -> Multikey.decode("z" + Base58.encode(unknown)));
    }

    private static byte[] unsigned(byte[] bytes, int length) {
        byte[] out = new byte[length];
        int copy = Math.min(bytes.length, length);
        System.arraycopy(bytes, bytes.length - copy, out, length - copy, copy);
        return out;
    }
}
