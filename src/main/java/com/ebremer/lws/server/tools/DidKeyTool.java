package com.ebremer.lws.server.tools;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.ebremer.lws.server.auth.Base58;

/**
 * Command-line helper to bootstrap a storage owner using the self-signed {@code did:key}
 * authentication suite — no identity provider required.
 *
 * <p>It generates (or reuses) an Ed25519 key and prints: the {@code did:key} to put in
 * {@code lws.owners}, the private key seed (to re-mint tokens later), and a ready-to-use Bearer
 * token (a self-issued JWT with {@code sub}=={@code iss}=={@code client_id}==the DID).
 *
 * <pre>
 *   java -cp lws-server.jar com.ebremer.lws.server.tools.DidKeyTool [--key &lt;seed&gt;] [--ttl &lt;seconds&gt;] [--audience &lt;aud&gt;]
 * </pre>
 *
 * @author Erich Bremer
 */
public final class DidKeyTool {

    private DidKeyTool() {
    }

    /** The result of minting: the DID, the reusable private-key seed, and a Bearer token. */
    public record Minted(String did, String privateKeySeedBase64Url, String token) {
    }

    /**
     * Mint a did:key and a self-issued token for it.
     *
     * @param seed        an existing 32-byte Ed25519 seed to reuse, or {@code null} to generate one
     * @param ttlSeconds  token lifetime
     * @param audience    optional {@code aud} claim, or {@code null}
     */
    public static Minted mint(byte[] seed, long ttlSeconds, String audience) {
        Ed25519PrivateKeyParameters priv = (seed != null)
                ? new Ed25519PrivateKeyParameters(seed, 0)
                : generateKey();
        byte[] pub = priv.generatePublicKey().getEncoded();

        byte[] multicodec = new byte[pub.length + 2];
        multicodec[0] = (byte) 0xed;
        multicodec[1] = 0x01;
        System.arraycopy(pub, 0, multicodec, 2, pub.length);
        String did = "did:key:z" + Base58.encode(multicodec);

        Instant now = Instant.now();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).type(JOSEObjectType.JWT).build();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .subject(did).issuer(did).claim("client_id", did)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(ttlSeconds)));
        if (audience != null && !audience.isBlank()) {
            claims.audience(audience);
        }
        return new Minted(did, base64Url(priv.getEncoded()), sign(header, claims.build(), priv));
    }

    private static Ed25519PrivateKeyParameters generateKey() {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        return (Ed25519PrivateKeyParameters) gen.generateKeyPair().getPrivate();
    }

    private static String sign(JWSHeader header, JWTClaimsSet claims, Ed25519PrivateKeyParameters priv) {
        String signingInput = header.toBase64URL() + "." + new Payload(claims.toJSONObject()).toBase64URL();
        byte[] toSign = signingInput.getBytes(StandardCharsets.US_ASCII);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, priv);
        signer.update(toSign, 0, toSign.length);
        return signingInput + "." + Base64URL.encode(signer.generateSignature());
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static void main(String[] args) {
        byte[] seed = null;
        long ttl = 3600;
        String audience = null;
        for (int i = 0; i + 1 < args.length; i += 2) {
            switch (args[i]) {
                case "--key" -> seed = Base64.getUrlDecoder().decode(args[i + 1]);
                case "--ttl" -> ttl = Long.parseLong(args[i + 1]);
                case "--audience" -> audience = args[i + 1];
                default -> { }
            }
        }
        Minted m = mint(seed, ttl, audience);
        System.out.println("LWS did:key owner token");
        System.out.println("=======================");
        System.out.println();
        System.out.println("Owner DID - set this in lws.owners:");
        System.out.println("  lws.owners=" + m.did());
        System.out.println();
        System.out.println("Private key seed (base64url) - keep secret; pass with --key to re-mint:");
        System.out.println("  " + m.privateKeySeedBase64Url());
        System.out.println();
        System.out.println("Bearer token (valid " + ttl + "s) - use as 'Authorization: Bearer <token>':");
        System.out.println("  " + m.token());
    }
}
