package com.ebremer.lws.server.auth;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * Decodes a {@code Multikey} public key — a CID 1.0 {@code publicKeyMultibase}, and the
 * method-specific identifier of a {@code did:key} — into a JWK.
 *
 * <p>The value is {@code z} (base58btc) followed by a multicodec header (an unsigned varint) and the
 * raw key. The key types this server verifies are Ed25519 ({@code 0xed}), and P-256
 * ({@code 0x1200}), P-384 ({@code 0x1201}) and secp256k1 ({@code 0xe7}) in the compressed point form
 * CID 1.0 §2.2.2 requires.
 *
 * <p>Two things are refused outright rather than decoded as well as possible:
 * <ul>
 *   <li>a <strong>non-canonical encoding</strong> — one that does not re-encode to the same text, such
 *       as a base58 string with superfluous leading zero digits — because one key must have one
 *       spelling, or two identifiers name the same subject;</li>
 *   <li>a <strong>private key header</strong> (the multicodec range {@code 0x1300}–{@code 0x1310}),
 *       which means the document published a secret key and has to be treated as compromised, not
 *       used.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
final class Multikey {

    private Multikey() {
    }

    private static final int ED25519_PUB = 0xed;
    private static final int SECP256K1_PUB = 0xe7;
    private static final int P256_PUB = 0x1200;
    private static final int P384_PUB = 0x1201;

    /** A decoded public key: its JWK and the JWS algorithm it signs with. */
    record Decoded(JWK jwk, JWSAlgorithm algorithm) {
    }

    /**
     * Decode a {@code z}-prefixed multibase value.
     *
     * @throws IllegalArgumentException if it is not a canonically encoded public key of a supported type
     */
    static Decoded decode(String multibase) {
        if (multibase == null || multibase.length() < 2 || multibase.charAt(0) != 'z') {
            throw new IllegalArgumentException("a Multikey value must be base58btc multibase ('z')");
        }
        byte[] data;
        try {
            data = Base58.decode(multibase.substring(1));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("not base58btc: " + e.getMessage());
        }
        if (!("z" + Base58.encode(data)).equals(multibase)) {
            throw new IllegalArgumentException("not the canonical encoding of its key");
        }
        long code = 0;
        int shift = 0;
        int i = 0;
        while (true) {
            if (i >= data.length || i > 3) {
                throw new IllegalArgumentException("truncated or oversized multicodec header");
            }
            int b = data[i++] & 0xff;
            code |= (long) (b & 0x7f) << shift;
            if ((b & 0x80) == 0) {
                break;
            }
            shift += 7;
        }
        if (code >= 0x1300 && code <= 0x1310) {
            throw new IllegalArgumentException("the value is a PRIVATE key (multicodec 0x"
                    + Long.toHexString(code) + "); it must never be published");
        }
        byte[] key = Arrays.copyOfRange(data, i, data.length);
        return switch ((int) code) {
            case ED25519_PUB -> {
                requireLength(key, 32, "Ed25519");
                yield new Decoded(new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(key))
                        .algorithm(JWSAlgorithm.EdDSA).build(), JWSAlgorithm.EdDSA);
            }
            case P256_PUB -> new Decoded(ec(Curve.P_256, "secp256r1", key, 32, JWSAlgorithm.ES256), JWSAlgorithm.ES256);
            case P384_PUB -> new Decoded(ec(Curve.P_384, "secp384r1", key, 48, JWSAlgorithm.ES384), JWSAlgorithm.ES384);
            case SECP256K1_PUB -> new Decoded(ec(Curve.SECP256K1, "secp256k1", key, 32, JWSAlgorithm.ES256K),
                    JWSAlgorithm.ES256K);
            default -> throw new IllegalArgumentException("unsupported multicodec key type 0x" + Long.toHexString(code));
        };
    }

    private static void requireLength(byte[] key, int length, String type) {
        if (key.length != length) {
            throw new IllegalArgumentException(type + " key must be " + length + " bytes, not " + key.length);
        }
    }

    private static ECKey ec(Curve curve, String bcCurveName, byte[] compressedPoint, int fieldBytes,
            JWSAlgorithm alg) {
        if (compressedPoint.length != fieldBytes + 1
                || (compressedPoint[0] != 0x02 && compressedPoint[0] != 0x03)) {
            throw new IllegalArgumentException(curve + " key must be a " + (fieldBytes + 1)
                    + "-byte compressed point");
        }
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(bcCurveName);
        org.bouncycastle.math.ec.ECPoint point;
        try {
            point = spec.getCurve().decodePoint(compressedPoint).normalize();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("not a point on " + curve);
        }
        byte[] x = fixedLength(point.getAffineXCoord().toBigInteger(), fieldBytes);
        byte[] y = fixedLength(point.getAffineYCoord().toBigInteger(), fieldBytes);
        return new ECKey.Builder(curve, Base64URL.encode(x), Base64URL.encode(y)).algorithm(alg).build();
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
