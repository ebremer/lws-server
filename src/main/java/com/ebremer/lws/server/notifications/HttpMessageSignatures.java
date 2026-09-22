package com.ebremer.lws.server.notifications;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Locale;

/**
 * Produces RFC 9421 HTTP Message Signatures (and the RFC 9530 {@code Content-Digest}) for
 * outbound webhook deliveries, as required by the LWS webhook notification suite: signatures cover
 * {@code @method}, {@code @scheme}, {@code @authority}, {@code @path}, {@code content-type} and
 * {@code content-digest}, with {@code created} and {@code keyid} signature parameters.
 *
 * <p>The {@code keyid} is the {@code id} of the signing key's verification method in the storage
 * description — a URL with a fragment, whose fragment-less part is the storage URI — because that is
 * how a receiver finds the key: it removes the fragment, dereferences the storage identifier and
 * looks the method up by {@code id}.
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

    /** Sign with the key's bare thumbprint as {@code keyid}; for callers with no storage to name. */
    public static SignatureHeaders sign(String method, URI target, String contentType,
            byte[] body, WebhookKeys keys, long createdEpochSeconds) {
        return sign(method, target, contentType, body, keys, keys.keyId(), createdEpochSeconds);
    }

    /**
     * Sign a delivery.
     *
     * @param keyId the {@code keyid} to name: the {@code id} of the key's verification method in the
     *              storage description
     */
    public static SignatureHeaders sign(String method, URI target, String contentType,
            byte[] body, WebhookKeys keys, String keyId, long createdEpochSeconds) {
        String contentDigest = "sha-256=:" + base64(sha256(body)) + ":";
        String params = COMPONENTS + ";created=" + createdEpochSeconds
                + ";keyid=\"" + keyId + "\";alg=\"ed25519\"";

        String authority = authorityOf(target);
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

    /**
     * The normalized authority a verifier will reconstruct, per RFC 9421 &sect;2.2.3.
     *
     * <p>{@code URI.getPort()} returns the port as <em>written</em>, so an inbox recorded as
     * {@code https://host:443/hook} was signed over {@code host:443} while the wire {@code Host}
     * header carries {@code host} — RFC 3986 &sect;6.2.3 makes a scheme's default port equivalent to
     * no port at all, and a client does not send it. A conformant verifier therefore rebuilt a
     * different base and rejected <em>every</em> delivery to that inbox as forged (finding M35).
     * Nothing on this side noticed: the rejection came back as a 4xx from the subscriber, was
     * retried, and eventually deactivated the subscription — a correct subscriber presenting as a
     * broken one.
     */
    private static String authorityOf(URI target) {
        String host = target.getHost() == null ? "" : target.getHost().toLowerCase(Locale.ROOT);
        int port = target.getPort();
        String scheme = target.getScheme() == null ? "" : target.getScheme().toLowerCase(Locale.ROOT);
        if (port == -1 || port == defaultPortFor(scheme)) {
            return host;
        }
        return host + ":" + port;
    }

    private static int defaultPortFor(String scheme) {
        return switch (scheme) {
            case "https" -> 443;
            case "http" -> 80;
            default -> -1;
        };
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
