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
import com.ebremer.lws.server.core.SecureFiles;

/**
 * The server's Ed25519 signing key for outbound webhook notifications. The private seed is
 * persisted so the key's identifier (an RFC 7638 JWK thumbprint) is stable across restarts.
 *
 * <p>The public key is published in the storage description, as a {@code JsonWebKey} verification
 * method whose {@code id} is the storage URI with the thumbprint as its fragment — that {@code id}
 * is the {@code keyid} a delivery's signature names (lws10-notifications-webhook) — and, as before,
 * in the JWK set at the JWKS endpoint.
 *
 * @author Erich Bremer
 */
public final class WebhookKeys {

    private static final Logger log = LoggerFactory.getLogger(WebhookKeys.class);

    private final Ed25519PrivateKeyParameters privateKey;
    private final Ed25519PublicKeyParameters publicKey;
    private final String keyId;

    /** The Ed25519 seed length; anything else cannot be a key this server wrote. */
    private static final int SEED_BYTES = Ed25519PrivateKeyParameters.KEY_SIZE;

    public WebhookKeys(Path keysDir) {
        try {
            SecureFiles.createDirectoriesOwnerOnly(keysDir);
            Path keyFile = keysDir.resolve("webhook-ed25519.key");
            this.privateKey = Files.isRegularFile(keyFile) ? readSeed(keyFile) : generateSeed(keyFile);
            this.publicKey = privateKey.generatePublicKey();
            this.keyId = thumbprint(publicKey.getEncoded());
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot initialize webhook keys", e);
        }
    }

    /**
     * Read the stored seed, refusing anything that is not exactly {@link #SEED_BYTES} bytes.
     *
     * <p>Neither failure used to be reported as one. A malformed file reached
     * {@code Base64.getUrlDecoder()}, which raises {@link IllegalArgumentException} — not an
     * {@link IOException}, so it went straight past the constructor's catch — and a short seed
     * reached BouncyCastle, which answered with a bare
     * {@code ArrayIndexOutOfBoundsException: arraycopy}. Either way the operator got a stack trace
     * about array bounds for what is really "this file is not the key" (finding M36).
     */
    private static Ed25519PrivateKeyParameters readSeed(Path keyFile) throws IOException {
        byte[] seed;
        try {
            seed = Base64.getUrlDecoder().decode(Files.readString(keyFile, StandardCharsets.UTF_8).trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "The webhook signing key at " + keyFile + " is not valid base64url; "
                            + "remove it to have a new one generated (subscribers must re-fetch the JWKS)", e);
        }
        if (seed.length != SEED_BYTES) {
            throw new IllegalStateException(
                    "The webhook signing key at " + keyFile + " is " + seed.length + " bytes, not "
                            + SEED_BYTES + "; remove it to have a new one generated "
                            + "(subscribers must re-fetch the JWKS)");
        }
        return new Ed25519PrivateKeyParameters(seed, 0);
    }

    /**
     * Generate a seed and put it on disk in one step that either happens or does not.
     *
     * <p>It used to be a plain {@code writeString}: default permissions, and a truncate-then-write
     * that a kill in the middle leaves as an empty or partial file. Anyone who can read the seed can
     * forge RFC 9421 signatures that verify against this storage's published JWKS, so it goes
     * through {@link SecureFiles#writeOwnerOnly} — owner-only from creation, moved into place
     * atomically, and never replacing a file another process won the race to write, because that
     * process's key is the one subscribers will verify against.
     */
    private static Ed25519PrivateKeyParameters generateSeed(Path keyFile) throws IOException {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricKeyParameter priv = gen.generateKeyPair().getPrivate();
        Ed25519PrivateKeyParameters key = (Ed25519PrivateKeyParameters) priv;

        String encoded = b64url(key.getEncoded());
        if (!SecureFiles.writeOwnerOnly(keyFile, writer -> writer.write(encoded))) {
            log.info("Webhook signing key at {} was created concurrently; using it", keyFile);
            return readSeed(keyFile);
        }
        log.info("Generated webhook signing key at {}", keyFile);
        return key;
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
        return "{\"keys\":[" + publicJwk() + "]}";
    }

    /** The public verification key as a JWK (RFC 8037), with its thumbprint as {@code kid}. */
    public jakarta.json.JsonObject publicJwk() {
        return jakarta.json.Json.createObjectBuilder()
                .add("kty", "OKP")
                .add("crv", "Ed25519")
                .add("alg", "EdDSA")
                .add("use", "sig")
                .add("kid", keyId)
                .add("x", b64url(publicKey.getEncoded()))
                .build();
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
