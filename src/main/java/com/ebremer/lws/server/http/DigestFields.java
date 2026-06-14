package com.ebremer.lws.server.http;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import com.ebremer.lws.server.core.LwsException;

/**
 * RFC 9530 Digest Fields: formats {@code Content-Digest}/{@code Repr-Digest} values, chooses an
 * algorithm from a {@code Want-*} field, and verifies an inbound {@code Content-Digest} against the
 * received content. Supports the spec's recommended secure algorithms, {@code sha-256} and
 * {@code sha-512}; other (deprecated) algorithms are ignored.
 *
 * @author Erich Bremer
 */
public final class DigestFields {

    private DigestFields() {
    }

    /** Supported algorithms, strongest first (used for tie-breaking a {@code Want-*} preference). */
    public static final List<String> SUPPORTED = List.of("sha-512", "sha-256");
    /** The supported algorithms as a set. */
    public static final Set<String> SUPPORTED_SET = Set.of("sha-256", "sha-512");

    /**
     * The value advertised in a {@code Want-Content-Digest} response field (RFC 9530 §4) to invite
     * integrity-protected requests: both supported algorithms, equally acceptable (a structured-fields
     * dictionary of algorithm to preference).
     */
    public static final String WANT = "sha-256=1, sha-512=1";

    /** Format a single-algorithm digest field value, e.g. {@code sha-256=:base64:}. */
    public static String format(String algorithm, byte[] content) {
        return algorithm + "=:" + Base64.getEncoder().encodeToString(digest(algorithm, content)) + ":";
    }

    /** Format a {@code sha-256} digest field value from a stored hex digest (avoids re-hashing). */
    public static String sha256FromHex(String hex) {
        return "sha-256=:" + Base64.getEncoder().encodeToString(HexFormat.of().parseHex(hex)) + ":";
    }

    /**
     * Choose the most-preferred algorithm a {@code Want-*} header requests that is in {@code available}.
     * Weights are integers (higher preferred; 0 = unacceptable); ties favour the stronger algorithm.
     */
    public static Optional<String> chooseAlgorithm(String wantHeader, Set<String> available) {
        if (wantHeader == null || wantHeader.isBlank()) {
            return Optional.empty();
        }
        String best = null;
        long bestWeight = 0;
        for (String member : wantHeader.split(",")) {
            String token = member.trim();
            if (token.isEmpty()) {
                continue;
            }
            int eq = token.indexOf('=');
            String algorithm = (eq < 0 ? token : token.substring(0, eq)).trim().toLowerCase(Locale.ROOT);
            long weight = 1;
            if (eq >= 0) {
                try {
                    weight = Long.parseLong(token.substring(eq + 1).trim());
                } catch (NumberFormatException e) {
                    weight = 1;
                }
            }
            if (weight > 0 && available.contains(algorithm)
                    && (best == null || weight > bestWeight
                        || (weight == bestWeight && SUPPORTED.indexOf(algorithm) < SUPPORTED.indexOf(best)))) {
                best = algorithm;
                bestWeight = weight;
            }
        }
        return Optional.ofNullable(best);
    }

    /**
     * Verify an inbound {@code Content-Digest} against the received content: every supported
     * algorithm present MUST match. Unsupported algorithms are ignored; a malformed field or a
     * mismatch is a {@code 400}.
     */
    public static void verify(String contentDigestHeader, byte[] content) {
        if (contentDigestHeader == null || contentDigestHeader.isBlank()) {
            return;
        }
        for (String member : contentDigestHeader.split(",")) {
            String token = member.trim();
            int eq = token.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String algorithm = token.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            if (!SUPPORTED_SET.contains(algorithm)) {
                continue; // can't verify an algorithm we don't support
            }
            String value = token.substring(eq + 1).trim();
            if (value.length() < 2 || value.charAt(0) != ':' || value.charAt(value.length() - 1) != ':') {
                throw LwsException.badRequest("Malformed Content-Digest for " + algorithm);
            }
            byte[] provided;
            try {
                provided = Base64.getDecoder().decode(value.substring(1, value.length() - 1));
            } catch (IllegalArgumentException e) {
                throw LwsException.badRequest("Malformed Content-Digest for " + algorithm);
            }
            if (!MessageDigest.isEqual(provided, digest(algorithm, content))) {
                throw LwsException.badRequest("Content-Digest mismatch for " + algorithm);
            }
        }
    }

    private static byte[] digest(String algorithm, byte[] content) {
        try {
            return MessageDigest.getInstance(jca(algorithm)).digest(content);
        } catch (Exception e) {
            throw new IllegalStateException(algorithm + " unavailable", e);
        }
    }

    private static String jca(String algorithm) {
        return switch (algorithm) {
            case "sha-256" -> "SHA-256";
            case "sha-512" -> "SHA-512";
            default -> throw new IllegalArgumentException("Unsupported digest algorithm: " + algorithm);
        };
    }
}
