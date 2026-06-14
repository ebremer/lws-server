package com.ebremer.lws.server.auth;

import java.io.StringReader;
import java.util.Optional;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Validates an LWS Self-signed Controlled Identifier (SSI-CID) authentication credential, per
 * <a href="https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/">LWS Authentication: Self-signed
 * Controlled Identifier</a>. The credential is a signed JWT whose {@code sub}, {@code iss} and
 * {@code client_id} are the same controlled-identifier URL; the JWT header {@code kid} selects a
 * {@code verificationMethod} (carrying a {@code publicKeyJwk}) in the dereferenced controlled
 * identifier document, which provides the verification key.
 *
 * @author Erich Bremer
 */
public final class SsiCidValidator implements CredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(SsiCidValidator.class);

    private final DocumentLoader loader;

    public SsiCidValidator(DocumentLoader loader) {
        this.loader = loader;
    }

    @Override
    public Optional<LwsPrincipal> validate(String credential) {
        try {
            SignedJWT jwt = SignedJWT.parse(credential);
            if (!JwsSupport.algNotNone(jwt)) {
                return Optional.empty();
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String sub = claims.getSubject();
            String iss = claims.getIssuer();
            String clientId = JwsSupport.clientId(claims);
            if (sub == null || !sub.equals(iss) || !sub.equals(clientId)) {
                return Optional.empty();
            }
            if (sub.startsWith("did:")) {
                return Optional.empty(); // DIDs are handled by their own suite
            }
            String kid = jwt.getHeader().getKeyID();
            if (kid == null) {
                log.debug("ssi-cid credential: JWT has no kid");
                return Optional.empty();
            }
            String docText = loader.load(sub);
            if (docText == null) {
                log.debug("ssi-cid credential: could not dereference subject {}", sub);
                return Optional.empty();
            }
            JsonObject doc;
            try (JsonReader reader = Json.createReader(new StringReader(docText))) {
                doc = reader.readObject();
            }
            if (!sub.equals(doc.getString("id", null))) {
                log.debug("ssi-cid credential: document id does not match subject");
                return Optional.empty();
            }
            JsonObject jwkJson = findPublicKeyJwk(doc, kid, sub);
            if (jwkJson == null) {
                log.debug("ssi-cid credential: no verificationMethod with a publicKeyJwk for kid {}", kid);
                return Optional.empty();
            }
            JWK jwk = JWK.parse(jwkJson.toString());
            if (!JwsSupport.verify(jwt, jwk)) {
                log.debug("ssi-cid credential: signature does not verify");
                return Optional.empty();
            }
            if (!JwsSupport.notExpired(claims)) {
                log.debug("ssi-cid credential: expired or missing exp");
                return Optional.empty();
            }
            return Optional.of(new LwsPrincipal(sub, iss, clientId));
        } catch (Exception e) {
            log.debug("ssi-cid validation failed: {}", e.toString());
            return Optional.empty();
        }
    }

    private static JsonObject findPublicKeyJwk(JsonObject doc, String kid, String sub) {
        if (!doc.containsKey("verificationMethod")
                || doc.get("verificationMethod").getValueType() != JsonValue.ValueType.ARRAY) {
            return null;
        }
        JsonArray methods = doc.getJsonArray("verificationMethod");
        for (JsonValue value : methods) {
            if (value.getValueType() != JsonValue.ValueType.OBJECT) {
                continue;
            }
            JsonObject vm = value.asJsonObject();
            String id = vm.getString("id", null);
            if (id != null && matchesKid(id, kid, sub)
                    && vm.containsKey("publicKeyJwk")
                    && vm.get("publicKeyJwk").getValueType() == JsonValue.ValueType.OBJECT) {
                return vm.getJsonObject("publicKeyJwk");
            }
        }
        return null;
    }

    private static boolean matchesKid(String vmId, String kid, String sub) {
        if (vmId.equals(kid)) {
            return true;
        }
        String fragment = kid.startsWith("#") ? kid : "#" + kid;
        return vmId.equals(sub + fragment) || vmId.endsWith(fragment);
    }
}
