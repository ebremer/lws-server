package com.ebremer.lws.server.notifications;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The server's Ed25519 signing key for outbound webhook notifications. The private seed is
 * persisted so the {@code keyid} (an RFC 7638 JWK thumbprint) is stable across restarts; the
 * public key is published as a JWK set at the JWKS endpoint for subscribers to verify
 * signatures.
 *
 * @author Erich Bremer
 */
public final class WebhookKeys {

    private static final Logger log = LoggerFactory.getLogger(WebhookKeys.class);

    private final Ed25519PrivateKeyParameters privateKey;
    private final Ed25519PublicKeyParameters publicKey;
    private final String keyId;

    public WebhookKeys(Path keysDir) {
        try {
            Files.createDirectories(keysDir);
            Path keyFile = keysDir.resolve("webhook-ed25519.key");
            if (Files.isRegularFile(keyFile)) {
                byte[] seed = Base64.getUrlDecoder().decode(Files.readString(keyFile).trim());
                this.privateKey = new Ed25519PrivateKeyParameters(seed, 0);
            } else {
                SecureRandom random = new SecureRandom();
                Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
                gen.init(new Ed25519KeyGenerationParameters(random));
                AsymmetricKeyParameter priv = gen.generateKeyPair().getPrivate();
                this.privateKey = (Ed25519PrivateKeyParameters) priv;
                Files.writeString(keyFile, b64url(privateKey.getEncoded()));
                log.info("Generated webhook signing key at {}", keyFile);
            }
            this.publicKey = privateKey.generatePublicKey();
            this.keyId = thumbprint(publicKey.getEncoded());
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot initialize webhook keys", e);
        }
    }

    public String keyId() {
        return keyId;
    }

    /** Sign bytes with Ed25519, returning the 64-byte signature. */
    public byte[] sign(byte[] data) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(data, 0, data.length);
        return signer.generateSignature();
    }

    /** The public verification key as a single-key JWK Set (JSON). */
    public String publicJwkSetJson() {
        String x = b64url(publicKey.getEncoded());
        return "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"EdDSA\",\"use\":\"sig\",\"kid\":\""
                + keyId + "\",\"x\":\"" + x + "\"}]}";
    }

    private static String thumbprint(byte[] publicKeyBytes) {
        // RFC 7638 JWK thumbprint over the canonical OKP member ordering.
        String canonical = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + b64url(publicKeyBytes) + "\"}";
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
            return b64url(hash);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
