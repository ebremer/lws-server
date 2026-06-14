package com.ebremer.lws.server.auth;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * A minimal in-process OpenID Connect provider for tests: serves OIDC discovery, a JWKS, and two
 * controlled-identifier documents (one that trusts this issuer as an {@code lws:OpenIdProvider},
 * one that does not), and mints signed RS256 ID tokens.
 */
public final class MockOidcProvider implements AutoCloseable {

    private final HttpServer server;
    private final String issuer;
    private final RSAKey signingKey;

    public MockOidcProvider() throws Exception {
        this.signingKey = new RSAKeyGenerator(2048).keyID("test-key").generate();
        this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        this.issuer = "http://localhost:" + server.getAddress().getPort();

        server.createContext("/.well-known/openid-configuration", e -> respond(e, "application/json", "{"
                + "\"issuer\":\"" + issuer + "\","
                + "\"authorization_endpoint\":\"" + issuer + "/authorize\","
                + "\"token_endpoint\":\"" + issuer + "/token\","
                + "\"jwks_uri\":\"" + issuer + "/jwks\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"subject_types_supported\":[\"public\"],"
                // private_key_jwt listed first, as Keycloak advertises it — a client configured
                // with only a secret must not adopt it.
                + "\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}"));
        server.createContext("/jwks", e ->
                respond(e, "application/json", new JWKSet(signingKey.toPublicJWK()).toString()));
        // Controlled identifier document that trusts this issuer as an OpenID provider.
        server.createContext("/profile", e -> respond(e, "text/turtle",
                "@prefix lws: <https://www.w3.org/ns/lws#> .\n"
                        + "<" + issuer + "/profile> lws:service "
                        + "[ a lws:OpenIdProvider ; lws:serviceEndpoint <" + issuer + "> ] ."));
        // The same trust expressed in the CID v1 shape: service/serviceEndpoint in the DID
        // namespace (where the https://www.w3.org/ns/cid/v1 context maps them).
        server.createContext("/profile-cid", e -> respond(e, "text/turtle",
                "@prefix did: <https://www.w3.org/ns/did#> .\n"
                        + "@prefix lws: <https://www.w3.org/ns/lws#> .\n"
                        + "<" + issuer + "/profile-cid> did:service "
                        + "[ a lws:OpenIdProvider ; did:serviceEndpoint <" + issuer + "> ] ."));
        // Controlled identifier document that does NOT advertise the provider.
        server.createContext("/untrusted", e -> respond(e, "text/turtle",
                "@prefix lws: <https://www.w3.org/ns/lws#> .\n<" + issuer + "/untrusted> a lws:DataResource ."));
        server.start();
    }

    public String issuer() {
        return issuer;
    }

    public String discoveryUri() {
        return issuer + "/.well-known/openid-configuration";
    }

    public String trustedSubject() {
        return issuer + "/profile";
    }

    /** A subject whose document uses the CID v1 shape ({@code did:service}/{@code did:serviceEndpoint}). */
    public String cidTrustedSubject() {
        return issuer + "/profile-cid";
    }

    public String untrustedSubject() {
        return issuer + "/untrusted";
    }

    public String mintIdToken(String subject, Instant expiry) throws Exception {
        return mintIdToken(subject, expiry, signingKey);
    }

    public String mintIdToken(String subject, Instant expiry, RSAKey key) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(key.getKeyID()).type(JOSEObjectType.JWT).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer).subject(subject).audience("lws-client")
                .claim("azp", "lws-client").issueTime(new Date()).expirationTime(Date.from(expiry)).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private static void respond(HttpExchange exchange, String contentType, String body) throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
