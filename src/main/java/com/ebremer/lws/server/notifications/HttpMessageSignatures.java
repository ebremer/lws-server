package com.ebremer.lws.server.notifications;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Produces RFC 9421 HTTP Message Signatures (and the RFC 9530 {@code Content-Digest}) for
 * outbound webhook deliveries, as required by the LWS notifications spec: signatures cover
 * {@code @method}, {@code @scheme}, {@code @authority}, {@code @path}, {@code content-type} and
 * {@code content-digest}, with {@code created} and {@code keyid} signature parameters.
 *
 * @author Erich Bremer
 */
public final class HttpMessageSignatures {

    private HttpMessageSignatures() {
    }

    /** The header values a signed delivery must carry. */
    public record SignatureHeaders(String contentDigest, String signatureInput, String signature) {
    }

    private static final String LABEL = "sig1";
    private static final String COMPONENTS =
            "(\"@method\" \"@scheme\" \"@authority\" \"@path\" \"content-type\" \"content-digest\")";

    public static SignatureHeaders sign(String method, URI target, String contentType,
            byte[] body, WebhookKeys keys, long createdEpochSeconds) {
        String contentDigest = "sha-256=:" + base64(sha256(body)) + ":";
        String params = COMPONENTS + ";created=" + createdEpochSeconds
                + ";keyid=\"" + keys.keyId() + "\";alg=\"ed25519\"";

        String authority = target.getHost() == null ? "" : target.getHost().toLowerCase();
        if (target.getPort() != -1) {
            authority = authority + ":" + target.getPort();
        }
        String path = (target.getRawPath() == null || target.getRawPath().isEmpty()) ? "/" : target.getRawPath();
        String scheme = target.getScheme() == null ? "https" : target.getScheme().toLowerCase();

        String base = String.join("\n",
                "\"@method\": " + method.toUpperCase(),
                "\"@scheme\": " + scheme,
                "\"@authority\": " + authority,
                "\"@path\": " + path,
                "\"content-type\": " + contentType,
                "\"content-digest\": " + contentDigest,
                "\"@signature-params\": " + params);

        byte[] sig = keys.sign(base.getBytes(StandardCharsets.UTF_8));
        String signatureInput = LABEL + "=" + params;
        String signature = LABEL + "=:" + base64(sig) + ":";
        return new SignatureHeaders(contentDigest, signatureInput, signature);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
