package com.ebremer.lws.server.auth;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Base58 (Bitcoin alphabet) encoding/decoding, used to parse {@code did:key} multibase values.
 *
 * @author Erich Bremer
 */
public final class Base58 {

    private Base58() {
    }

    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);
    private static final int[] INDEX = new int[128];

    static {
        Arrays.fill(INDEX, -1);
        for (int i = 0; i < ALPHABET.length(); i++) {
            INDEX[ALPHABET.charAt(i)] = i;
        }
    }

    public static byte[] decode(String input) {
        if (input.isEmpty()) {
            return new byte[0];
        }
        BigInteger num = BigInteger.ZERO;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEX[c] : -1;
            if (digit < 0) {
                throw new IllegalArgumentException("Illegal Base58 character: " + c);
            }
            num = num.multiply(BASE).add(BigInteger.valueOf(digit));
        }
        byte[] bytes = num.toByteArray();
        int from = (bytes.length > 1 && bytes[0] == 0) ? 1 : 0; // drop sign byte
        int zeros = 0;
        while (zeros < input.length() && input.charAt(zeros) == '1') {
            zeros++;
        }
        byte[] out = new byte[zeros + (bytes.length - from)];
        System.arraycopy(bytes, from, out, zeros, bytes.length - from);
        return out;
    }

    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            zeros++;
        }
        BigInteger num = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        while (num.signum() > 0) {
            BigInteger[] qr = num.divideAndRemainder(BASE);
            sb.append(ALPHABET.charAt(qr[1].intValue()));
            num = qr[0];
        }
        for (int i = 0; i < zeros; i++) {
            sb.append('1');
        }
        return sb.reverse().toString();
    }
}
