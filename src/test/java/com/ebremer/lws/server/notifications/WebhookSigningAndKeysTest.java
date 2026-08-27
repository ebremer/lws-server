package com.ebremer.lws.server.notifications;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Base64;
import java.util.Set;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The two halves of a webhook delivery a subscriber actually checks: the RFC 9421 signature base,
 * and the key that signs it (findings M35 and M36).
 *
 * @author Erich Bremer
 */
class WebhookSigningAndKeysTest {

    /**
     * RFC 9421 §2.2.3 derives {@code @authority} from the URI authority <em>normalized</em>, and
     * RFC 3986 §6.2.3 makes a scheme's default port equivalent to no port at all. So an inbox
     * written {@code https://host:443/hook} must be signed as {@code host} — the wire {@code Host}
     * header a client sends for it — and not {@code host:443}.
     *
     * <p>Signed the wrong way, a conformant verifier rebuilds the base from what it received, gets a
     * different string, and rejects <em>every</em> delivery to that inbox as forged. Nothing in the
     * server notices: the delivery is a 4xx from the subscriber, retried and eventually counted as a
     * failure, so a well-behaved subscriber looks like a broken one.
     */
    @Test
    void authorityIsNormalizedSoAConformantVerifierAccepts(@TempDir Path dir) {
        WebhookKeys keys = new WebhookKeys(dir);
        assertSignsAuthority(keys, "https://inbox.example:443/hook", "inbox.example");
        assertSignsAuthority(keys, "http://inbox.example:80/hook", "inbox.example");
        assertSignsAuthority(keys, "https://inbox.example/hook", "inbox.example");
        // A non-default port is part of the authority and must survive.
        assertSignsAuthority(keys, "https://inbox.example:8443/hook", "inbox.example:8443");
        assertSignsAuthority(keys, "http://inbox.example:8080/hook", "inbox.example:8080");
        // Host is case-insensitive and normalizes to lower case.
        assertSignsAuthority(keys, "https://INBOX.Example:443/hook", "inbox.example");
    }

    /**
     * Verify the signature against a base this test builds itself, so the assertion is what a
     * subscriber would compute rather than a rerun of the server's own arithmetic.
     */
    private static void assertSignsAuthority(WebhookKeys keys, String inbox, String expectedAuthority) {
        URI target = URI.create(inbox);
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        HttpMessageSignatures.SignatureHeaders sig =
                HttpMessageSignatures.sign("POST", target, "application/ld+json", body, keys, 1700000000L);

        String params = sig.signatureInput().substring(sig.signatureInput().indexOf('=') + 1);
        String base = String.join("\n",
                "\"@method\": POST",
                "\"@scheme\": " + target.getScheme(),
                "\"@authority\": " + expectedAuthority,
                "\"@path\": " + target.getRawPath(),
                "\"content-type\": application/ld+json",
                "\"content-digest\": " + sig.contentDigest(),
                "\"@signature-params\": " + params);

        String b64 = sig.signature().substring(sig.signature().indexOf(':') + 1, sig.signature().lastIndexOf(':'));
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKeyOf(keys));
        byte[] baseBytes = base.getBytes(StandardCharsets.UTF_8);
        verifier.update(baseBytes, 0, baseBytes.length);
        assertTrue(verifier.verifySignature(Base64.getDecoder().decode(b64)),
                inbox + " must sign @authority as \"" + expectedAuthority + "\"");
    }

    private static Ed25519PublicKeyParameters publicKeyOf(WebhookKeys keys) {
        String jwks = keys.publicJwkSetJson();
        String x = jwks.substring(jwks.indexOf("\"x\":\"") + 5, jwks.lastIndexOf("\"}]}"));
        return new Ed25519PublicKeyParameters(Base64.getUrlDecoder().decode(x), 0);
    }

    // ----- M36: the seed on disk -----

    @Test
    void theSeedIsStableAcrossRestartsAndNotWorldReadable(@TempDir Path dir) throws Exception {
        WebhookKeys first = new WebhookKeys(dir);
        WebhookKeys second = new WebhookKeys(dir);
        assertEquals(first.keyId(), second.keyId(), "the keyid must survive a restart");

        Path keyFile = dir.resolve("webhook-ed25519.key");
        assertTrue(Files.isRegularFile(keyFile));
        PosixFileAttributeView posix = Files.getFileAttributeView(keyFile, PosixFileAttributeView.class);
        if (posix != null) { // POSIX filesystems only; Windows has no equivalent view
            Set<PosixFilePermission> perms = posix.readAttributes().permissions();
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), perms,
                    "anyone who can read this seed can forge signatures that verify against the JWKS");
        }
    }

    /**
     * A seed that is not 32 bytes must stop the server with something an operator can act on. The
     * write is atomic now, so this is the leftover of an older non-atomic one — or of tampering —
     * and either way starting up with a key derived from truncated bytes would publish a JWKS no
     * subscriber can use.
     */
    @Test
    void aTruncatedOrCorruptSeedIsRefusedAtStartup(@TempDir Path dir) throws Exception {
        Path keyFile = dir.resolve("webhook-ed25519.key");
        Files.createDirectories(dir);

        Files.writeString(keyFile, Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[16]));
        RuntimeException short16 = assertThrows(RuntimeException.class, () -> new WebhookKeys(dir));
        assertTrue(short16.getMessage() != null && short16.getMessage().contains("webhook"),
                "the failure must name what is wrong: " + short16);

        // Not base64 at all — the decoder throws IllegalArgumentException, which is not an
        // IOException and used to escape the constructor's catch unannotated.
        Files.writeString(keyFile, "this is not base64!!");
        assertThrows(RuntimeException.class, () -> new WebhookKeys(dir));

        // An empty file, the shape a kill between truncate and write used to leave behind.
        Files.writeString(keyFile, "");
        assertThrows(RuntimeException.class, () -> new WebhookKeys(dir));
    }

    @Test
    void twoStoragesGetDifferentKeys(@TempDir Path a, @TempDir Path b) {
        assertNotEquals(new WebhookKeys(a).keyId(), new WebhookKeys(b).keyId());
    }
}
