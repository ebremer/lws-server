package com.ebremer.lws.server.oauth;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.core.SecureFiles;

/**
 * The embedded authorization server's access-token signing key: a P-256 key used with
 * {@code ES256}, persisted owner-only so the tokens it signed stay verifiable across a restart, and
 * published — public half only — in the storage's JWK set, which is the {@code jwks_uri} of the
 * authorization server metadata.
 *
 * <p>Its {@code kid} is its RFC 7638 thumbprint, so it changes exactly when the key does. Rotating
 * is removing the key file and restarting: tokens signed by the old key then fail validation, and
 * since they live {@code lws.oauth.access-token-lifetime-seconds} at most, clients recover by
 * exchanging their credential again.
 *
 * @author Erich Bremer
 */
public final class AccessTokenKeys {

    private static final Logger log = LoggerFactory.getLogger(AccessTokenKeys.class);

    /** RFC 9068 §2.1: an access token's {@code typ} header is {@code at+jwt}. */
    public static final JOSEObjectType AT_JWT = new JOSEObjectType("at+jwt");

    private final ECKey key;

    public AccessTokenKeys(Path keysDir) {
        try {
            SecureFiles.createDirectoriesOwnerOnly(keysDir);
            Path file = keysDir.resolve("oauth-es256.jwk");
            this.key = Files.isRegularFile(file) ? read(file) : generate(file);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot initialize the access-token signing key", e);
        }
    }

    private static ECKey read(Path file) throws IOException {
        try {
            JWK jwk = JWK.parse(Files.readString(file, StandardCharsets.UTF_8));
            if (!(jwk instanceof ECKey ec) || !ec.isPrivate() || !Curve.P_256.equals(ec.getCurve())) {
                throw new IllegalStateException("The access-token signing key at " + file
                        + " is not a private P-256 key; remove it to have a new one generated");
            }
            return ec;
        } catch (ParseException e) {
            throw new IllegalStateException("The access-token signing key at " + file
                    + " is not a JWK; remove it to have a new one generated", e);
        }
    }

    private static ECKey generate(Path file) throws IOException {
        ECKey generated;
        try {
            ECKey raw = new ECKeyGenerator(Curve.P_256).generate();
            generated = new ECKey.Builder(raw)
                    .keyID(raw.computeThumbprint().toString())
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256)
                    .build();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot generate a P-256 key", e);
        }
        String json = generated.toJSONString();
        if (!SecureFiles.writeOwnerOnly(file, writer -> writer.write(json))) {
            log.info("Access-token signing key at {} was created concurrently; using it", file);
            return read(file);
        }
        log.info("Generated access-token signing key at {}", file);
        return generated;
    }

    public String keyId() {
        return key.getKeyID();
    }

    /** The public verification key. */
    public JWK publicJwk() {
        return key.toPublicJWK();
    }

    /** The public verification key as a single-key JWK set. */
    public JWKSet publicJwkSet() {
        return new JWKSet(publicJwk());
    }

    /** Sign {@code claims} as an RFC 9068 access token: {@code ES256}, {@code typ: at+jwt}, this {@code kid}. */
    public String sign(JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(AT_JWT)
                    .keyID(key.getKeyID())
                    .build(), claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign an access token", e);
        }
    }
}
