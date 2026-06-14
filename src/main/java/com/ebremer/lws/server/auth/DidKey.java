package com.ebremer.lws.server.auth;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * Parses a {@code did:key} identifier into its public verification key, per the did:key method:
 * the identifier is {@code did:key:z<base58btc(multicodec-prefix || raw-public-key)>}.
 *
 * <p>Supports Ed25519 ({@code 0xed01}), NIST P-256 ({@code 0x1200}) and secp256k1
 * ({@code 0xe701}).
 *
 * @author Erich Bremer
 */
final class DidKey {

    private DidKey() {
    }

    static final String PREFIX = "did:key:";

    static JWK toPublicJwk(String did) {
        String multibase = did.substring(PREFIX.length());
        if (multibase.isEmpty() || multibase.charAt(0) != 'z') {
            throw new IllegalArgumentException("did:key must use base58btc multibase ('z')");
        }
        byte[] data = Base58.decode(multibase.substring(1));
        if (data.length < 3) {
            throw new IllegalArgumentException("did:key value too short");
        }
        int p0 = data[0] & 0xff;
        int p1 = data[1] & 0xff;
        byte[] key = Arrays.copyOfRange(data, 2, data.length);
        if (p0 == 0xed && p1 == 0x01) {
            return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(key)).build();
        }
        if (p0 == 0x80 && p1 == 0x24) {
            return ec(Curve.P_256, "secp256r1", key);
        }
        if (p0 == 0xe7 && p1 == 0x01) {
            return ec(Curve.SECP256K1, "secp256k1", key);
        }
        throw new IllegalArgumentException(
                "Unsupported did:key multicodec: 0x" + Integer.toHexString(p0) + Integer.toHexString(p1));
    }

    private static ECKey ec(Curve curve, String bcCurveName, byte[] compressedPoint) {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(bcCurveName);
        org.bouncycastle.math.ec.ECPoint point = spec.getCurve().decodePoint(compressedPoint).normalize();
        byte[] x = fixedLength(point.getAffineXCoord().toBigInteger(), 32);
        byte[] y = fixedLength(point.getAffineYCoord().toBigInteger(), 32);
        return new ECKey.Builder(curve, Base64URL.encode(x), Base64URL.encode(y)).build();
    }

    private static byte[] fixedLength(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        byte[] out = new byte[length];
        if (bytes.length > length) {
            System.arraycopy(bytes, bytes.length - length, out, 0, length);
        } else {
            System.arraycopy(bytes, 0, out, length - bytes.length, bytes.length);
        }
        return out;
    }
}
