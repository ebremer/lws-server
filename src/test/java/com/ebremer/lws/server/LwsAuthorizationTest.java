package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * The LWS authorization framework over real sockets (lws10-core, Authorization): the embedded
 * authorization server's metadata and token exchange, the storage's validation of the access tokens
 * it — or a trusted external authorization server — issues, the {@code as_uri}/{@code realm}
 * challenge that tells a client where to go, and DPoP-bound tokens (RFC 9449 §5).
 *
 * <p>Two storages: one with the defaults, which still honours an authentication credential
 * presented directly, and one with {@code lws.oauth.accept-authentication-credentials=false}, which
 * accepts access tokens only. A stub external authorization server — RFC 8414 metadata at
 * {@code /.well-known/lws-configuration} and a JWK set — is trusted by the first.
 *
 * @author Erich Bremer
 */
class LwsAuthorizationTest {

    private static final Path tempDir = TestDirs.create();
    private static final Path strictDir = TestDirs.create();

    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    private static final String DOC = "/private-doc";

    private static HttpClient http;
    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static Server strictServer;
    private static LwsComponents strictComponents;
    private static String strictUrl;

    private static HttpServer externalAs;
    private static String externalIssuer;
    private static ECKey externalKey;

    private static DidKeyTool.Minted owner;
    private static String ownerSeed;

    @BeforeAll
    static void start() throws Exception {
        http = HttpClient.newHttpClient();

        // The external authorization server: metadata naming itself and a JWK set.
        externalKey = ecKey("ext-1");
        externalAs = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        externalIssuer = "http://localhost:" + externalAs.getAddress().getPort();
        String metadata = Json.createObjectBuilder()
                .add("issuer", externalIssuer)
                .add("jwks_uri", externalIssuer + "/jwks")
                .add("token_endpoint", externalIssuer + "/token")
                .build().toString();
        String jwks = new JWKSet(externalKey.toPublicJWK()).toString();
        externalAs.createContext("/.well-known/lws-configuration", exchange -> respond(exchange, metadata));
        externalAs.createContext("/jwks", exchange -> respond(exchange, jwks));
        externalAs.start();

        int port = freePort();
        baseUrl = "http://localhost:" + port;
        owner = DidKeyTool.mint(null, 3600, baseUrl);
        ownerSeed = owner.privateKeySeedBase64Url();

        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.data-dir", tempDir.toString());
        p.setProperty("lws.owners", owner.did());
        p.setProperty("lws.public-read", "false");
        p.setProperty("lws.oauth.trusted-issuers", externalIssuer);
        p.setProperty("lws.fetch.allowed-hosts", "localhost"); // the stub authorization server
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();

        int strictPort = freePort();
        strictUrl = "http://localhost:" + strictPort;
        Properties s = new Properties();
        s.setProperty("lws.base-uri", strictUrl);
        s.setProperty("lws.data-dir", strictDir.toString());
        s.setProperty("lws.owners", owner.did());
        s.setProperty("lws.public-read", "false");
        s.setProperty("lws.oauth.accept-authentication-credentials", "false");
        LwsConfiguration strictConfig = LwsConfiguration.of(s);
        strictComponents = LwsComponents.create(strictConfig);
        strictServer = new Server(strictPort);
        strictServer.setHandler(JettyLauncher.buildHandler(strictComponents, strictConfig));
        strictServer.start();

        // The fixture, written with a credential presented directly (the default storage allows it).
        HttpResponse<String> put = send("PUT", baseUrl + DOC, "Bearer " + owner.token(), "text/turtle",
                "<#it> <http://schema.org/name> \"fixture\" .");
        assertEquals(201, put.statusCode(), put.body());
    }

    @AfterAll
    static void stop() throws Exception {
        if (server != null) {
            server.stop();
        }
        if (components != null) {
            components.close();
        }
        if (strictServer != null) {
            strictServer.stop();
        }
        if (strictComponents != null) {
            strictComponents.close();
        }
        if (externalAs != null) {
            externalAs.stop(0);
        }
    }

    // ----- discovery -----

    @Test
    void theAuthorizationServerPublishesItsMetadata() throws Exception {
        HttpResponse<String> r = send("GET", baseUrl + "/.well-known/lws-configuration", null, null, null);
        assertEquals(200, r.statusCode());
        JsonObject md = parse(r.body());
        assertEquals(baseUrl, md.getString("issuer"));
        assertEquals(baseUrl + "/.lws/token", md.getString("token_endpoint"));
        assertEquals(baseUrl + "/.lws/jwks", md.getString("jwks_uri"));
        assertTrue(md.getJsonArray("grant_types_supported").toString().contains(TOKEN_EXCHANGE));
        assertTrue(md.getJsonArray("subject_token_types_supported").toString().contains(JWT_TYPE));
        assertTrue(md.getJsonArray("subject_token_types_supported").toString()
                .contains("urn:ietf:params:oauth:token-type:id_token"));
        assertEquals(Json.createArrayBuilder().add("https").add("did:key").add("did:web").build(),
                md.getJsonArray("subject_identifier_types_supported"));
    }

    /**
     * A 401 names the authorization server and the storage (lws10-core, Authorization Server
     * Discovery): {@code as_uri} is where to get a token, {@code realm} what to ask it for — and
     * the requested URI is logically contained in the realm.
     */
    @Test
    void aRefusalCarriesAConformingChallenge() throws Exception {
        HttpResponse<String> r = send("GET", baseUrl + DOC, null, null, null);
        assertEquals(401, r.statusCode());
        List<String> challenges = r.headers().allValues("WWW-Authenticate");
        assertTrue(challenges.stream().anyMatch(c -> c.startsWith(
                "Bearer as_uri=\"" + baseUrl + "\", realm=\"" + baseUrl + "/\"")), challenges.toString());
        assertTrue((baseUrl + DOC).startsWith(baseUrl + "/"), "the realm contains the request URI");
        assertTrue(r.headers().allValues("Link")
                .contains("<" + baseUrl + "/>; rel=\"https://www.w3.org/ns/lws#storage\""));

        // An invalid token gets the same challenge, with the error.
        HttpResponse<String> bad = send("GET", baseUrl + DOC, "Bearer not.a.token", null, null);
        assertEquals(401, bad.statusCode());
        assertTrue(bad.headers().firstValue("WWW-Authenticate").orElse("")
                .startsWith("Bearer as_uri=\"" + baseUrl + "\", realm=\"" + baseUrl + "/\", error=\"invalid_token\""));
    }

    // ----- token exchange -----

    @Test
    void aSelfSignedCredentialIsExchangedForAnAccessToken() throws Exception {
        String credential = DidKeyTool.mint(java.util.Base64.getUrlDecoder().decode(ownerSeed), 3600, baseUrl).token();
        HttpResponse<String> r = token(baseUrl, form("grant_type", TOKEN_EXCHANGE, "resource", baseUrl + "/",
                "subject_token", credential, "subject_token_type", JWT_TYPE), null);
        assertEquals(200, r.statusCode(), r.body());
        assertEquals("no-store", r.headers().firstValue("Cache-Control").orElse(""));
        JsonObject response = parse(r.body());
        assertEquals("Bearer", response.getString("token_type"));
        assertEquals("urn:ietf:params:oauth:token-type:access_token", response.getString("issued_token_type"));
        assertTrue(response.getInt("expires_in") > 0 && response.getInt("expires_in") <= 300);

        SignedJWT at = SignedJWT.parse(response.getString("access_token"));
        assertEquals("at+jwt", at.getHeader().getType().getType());
        assertEquals(JWSAlgorithm.ES256, at.getHeader().getAlgorithm());
        JWTClaimsSet claims = at.getJWTClaimsSet();
        assertEquals(baseUrl, claims.getIssuer());
        assertEquals(owner.did(), claims.getSubject());
        assertEquals(owner.did(), claims.getStringClaim("client_id"));
        assertEquals(List.of(baseUrl + "/"), claims.getAudience());
        assertNotNull(claims.getJWTID());
        assertNotNull(claims.getIssueTime());
        assertTrue(claims.getExpirationTime().getTime() - claims.getIssueTime().getTime() <= 300_000L);

        // The signing key is in the JWK set the metadata names.
        assertTrue(send("GET", baseUrl + "/.lws/jwks", null, null, null).body().contains(at.getHeader().getKeyID()));

        // And the storage accepts the token.
        HttpResponse<String> read = send("GET", baseUrl + DOC, "Bearer " + response.getString("access_token"), null, null);
        assertEquals(200, read.statusCode(), read.body());
        assertTrue(read.body().contains("fixture"));
    }

    @Test
    void theTokenEndpointRefusesWhatItCannotHonour() throws Exception {
        String credential = owner.token();
        assertError(token(baseUrl, form("resource", baseUrl + "/", "subject_token", credential,
                "subject_token_type", JWT_TYPE), null), 400, "invalid_request");
        assertError(token(baseUrl, form("grant_type", "client_credentials", "resource", baseUrl + "/"), null),
                400, "unsupported_grant_type");
        assertError(token(baseUrl, form("grant_type", TOKEN_EXCHANGE, "subject_token", credential,
                "subject_token_type", JWT_TYPE), null), 400, "invalid_request");
        // lws10-core: a resource naming an unknown or untrusted storage MUST be rejected.
        assertError(token(baseUrl, form("grant_type", TOKEN_EXCHANGE, "resource", "https://other.example/",
                "subject_token", credential, "subject_token_type", JWT_TYPE), null), 400, "invalid_target");
        assertError(token(baseUrl, form("grant_type", TOKEN_EXCHANGE, "resource", baseUrl + "/",
                "subject_token", "not-a-credential", "subject_token_type", JWT_TYPE), null), 400, "invalid_request");
        assertError(token(baseUrl, form("grant_type", TOKEN_EXCHANGE, "resource", baseUrl + "/",
                "subject_token", credential, "subject_token_type", "urn:example:unknown"), null),
                400, "invalid_request");
        // A credential whose audience names neither this server nor its token endpoint.
        String elsewhere = DidKeyTool.mint(null, 3600, "https://elsewhere.example").token();
        assertError(token(baseUrl, form("grant_type", TOKEN_EXCHANGE, "resource", baseUrl + "/",
                "subject_token", elsewhere, "subject_token_type", JWT_TYPE), null), 400, "invalid_request");
        // RFC 6749 §3.2: no parameter more than once.
        assertError(token(baseUrl, "grant_type=" + enc(TOKEN_EXCHANGE) + "&resource=" + enc(baseUrl + "/")
                + "&resource=" + enc(baseUrl + "/") + "&subject_token=" + enc(credential)
                + "&subject_token_type=" + enc(JWT_TYPE), null), 400, "invalid_request");
        assertEquals(405, send("GET", baseUrl + "/.lws/token", null, null, null).statusCode());
        assertEquals(400, send("POST", baseUrl + "/.lws/token", null, "application/json", "{}").statusCode());
    }

    // ----- access-token validation at the storage -----

    /** A trusted external authorization server's token is accepted: metadata, JWK set, checks. */
    @Test
    void anExternalAuthorizationServersTokenIsValidated() throws Exception {
        assertEquals(200, read(externalToken(claims(baseUrl + "/").build(), "at+jwt")), "a well-formed token");

        // Each check lws10-core names refuses the request on its own.
        assertEquals(401, read(externalToken(claims("https://other.example/").build(), "at+jwt")),
                "aud names another storage");
        assertEquals(401, read(externalToken(claims(baseUrl + "/").audience(List.of(baseUrl + "/",
                "https://other.example/")).build(), "at+jwt")), "aud with more than one value");
        assertEquals(401, read(externalToken(claims(baseUrl + "/")
                .expirationTime(new Date(System.currentTimeMillis() - 120_000)).build(), "at+jwt")), "expired");
        assertEquals(401, read(externalToken(claims(baseUrl + "/")
                .notBeforeTime(new Date(System.currentTimeMillis() + 600_000)).build(), "at+jwt")), "not yet valid");
        assertEquals(401, read(externalToken(claims(baseUrl + "/")
                .issueTime(new Date(System.currentTimeMillis() + 600_000)).build(), "at+jwt")), "issued in the future");
        assertEquals(401, read(externalToken(claims(baseUrl + "/").jwtID(null).build(), "at+jwt")), "no jti");
        assertEquals(401, read(externalToken(claims(baseUrl + "/").claim("client_id", null).build(), "at+jwt")),
                "no client_id");
        assertEquals(401, read(externalToken(claims(baseUrl + "/").build(), "JWT")), "not an RFC 9068 token");
        assertEquals(401, read(externalToken(claims(baseUrl + "/").issuer("http://untrusted.example").build(),
                "at+jwt")), "an issuer this storage does not trust");
        // Signed by a key the issuer does not publish.
        ECKey rogue = ecKey("ext-1");
        SignedJWT forged = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("at+jwt"))
                .keyID("ext-1").build(), claims(baseUrl + "/").build());
        forged.sign(new ECDSASigner(rogue));
        assertEquals(401, read(forged.serialize()), "a signature the issuer's keys do not verify");
    }

    /**
     * With {@code lws.oauth.accept-authentication-credentials=false} the storage accepts access
     * tokens only: the credential that works when exchanged is refused when presented directly.
     */
    @Test
    void aStorageCanRequireAccessTokens() throws Exception {
        String credential = DidKeyTool.mint(java.util.Base64.getUrlDecoder().decode(ownerSeed), 3600, strictUrl).token();
        HttpResponse<String> direct = send("PUT", strictUrl + "/strict-doc", "Bearer " + credential, "text/plain", "x");
        assertEquals(401, direct.statusCode(), "a credential presented directly is refused: " + direct.body());

        HttpResponse<String> exchanged = token(strictUrl, form("grant_type", TOKEN_EXCHANGE, "resource", strictUrl,
                "subject_token", credential, "subject_token_type", JWT_TYPE), null);
        assertEquals(200, exchanged.statusCode(), exchanged.body());
        String accessToken = parse(exchanged.body()).getString("access_token");
        assertEquals(List.of(strictUrl + "/"), SignedJWT.parse(accessToken).getJWTClaimsSet().getAudience(),
                "the resource without its slash names the same storage");
        HttpResponse<String> put = send("PUT", strictUrl + "/strict-doc", "Bearer " + accessToken, "text/plain", "x");
        assertEquals(201, put.statusCode(), put.body());

        // A token this storage's authorization server issued for the OTHER storage is refused here.
        String other = parse(token(baseUrl, form("grant_type", TOKEN_EXCHANGE, "resource", baseUrl + "/",
                "subject_token", DidKeyTool.mint(java.util.Base64.getUrlDecoder().decode(ownerSeed), 3600, baseUrl).token(),
                "subject_token_type", JWT_TYPE), null).body()).getString("access_token");
        assertEquals(401, send("GET", strictUrl + "/strict-doc", "Bearer " + other, null, null).statusCode());
    }

    // ----- DPoP (RFC 9449 §5) -----

    @Test
    void aDpopProofAtTheTokenEndpointBindsTheToken() throws Exception {
        ECKey proofKey = ecKey(null);
        String credential = DidKeyTool.mint(java.util.Base64.getUrlDecoder().decode(ownerSeed), 3600, baseUrl).token();
        String tokenProof = proof(proofKey, "POST", baseUrl + "/.lws/token", null);
        HttpResponse<String> r = token(baseUrl, form("grant_type", TOKEN_EXCHANGE, "resource", baseUrl + "/",
                "subject_token", credential, "subject_token_type", JWT_TYPE), tokenProof);
        assertEquals(200, r.statusCode(), r.body());
        JsonObject response = parse(r.body());
        assertEquals("DPoP", response.getString("token_type"));
        String accessToken = response.getString("access_token");
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) SignedJWT.parse(accessToken).getJWTClaimsSet().getClaim("cnf");
        assertEquals(proofKey.computeThumbprint().toString(), cnf.get("jkt"));

        // A bound token is refused as Bearer, and accepted with a proof by the same key.
        assertEquals(401, send("GET", baseUrl + DOC, "Bearer " + accessToken, null, null).statusCode());
        HttpRequest withProof = HttpRequest.newBuilder(URI.create(baseUrl + DOC))
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", proof(proofKey, "GET", baseUrl + DOC, ath(accessToken)))
                .GET().build();
        assertEquals(200, http.send(withProof, HttpResponse.BodyHandlers.ofString()).statusCode());

        // The token-request proof cannot be replayed.
        assertError(token(baseUrl, form("grant_type", TOKEN_EXCHANGE, "resource", baseUrl + "/",
                "subject_token", credential, "subject_token_type", JWT_TYPE), tokenProof), 400, "invalid_dpop_proof");
    }

    // ----- helpers -----

    private static JWTClaimsSet.Builder claims(String audience) {
        long now = System.currentTimeMillis();
        return new JWTClaimsSet.Builder()
                .issuer(externalIssuer)
                .subject(owner.did())
                .claim("client_id", "https://app.example/id")
                .audience(audience)
                .issueTime(new Date(now))
                .expirationTime(new Date(now + 300_000))
                .jwtID(UUID.randomUUID().toString());
    }

    private static String externalToken(JWTClaimsSet claims, String typ) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(typ))
                .keyID(externalKey.getKeyID()).build(), claims);
        jwt.sign(new ECDSASigner(externalKey));
        return jwt.serialize();
    }

    private static int read(String accessToken) throws Exception {
        return send("GET", baseUrl + DOC, "Bearer " + accessToken, null, null).statusCode();
    }

    private static void assertError(HttpResponse<String> r, int status, String error) {
        assertEquals(status, r.statusCode(), r.body());
        assertEquals(error, parse(r.body()).getString("error"), r.body());
        assertEquals("no-store", r.headers().firstValue("Cache-Control").orElse(""));
    }

    private static HttpResponse<String> token(String base, String form, String dpopProof) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + "/.lws/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form));
        if (dpopProof != null) {
            b.header("DPoP", dpopProof);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String form(String... pairs) {
        Map<String, String> params = new LinkedHashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            params.put(pairs[i], pairs[i + 1]);
        }
        StringBuilder sb = new StringBuilder();
        params.forEach((k, v) -> sb.append(sb.isEmpty() ? "" : "&").append(enc(k)).append('=').append(enc(v)));
        return sb.toString();
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static HttpResponse<String> send(String method, String url, String authorization, String contentType,
            String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body));
        if (authorization != null) {
            b.header("Authorization", authorization);
        }
        if (contentType != null) {
            b.header("Content-Type", contentType);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static JsonObject parse(String json) {
        try (var reader = Json.createReader(new StringReader(json))) {
            return reader.readObject();
        }
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String body) throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (var out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static ECKey ecKey(String kid) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        ECKey.Builder b = new ECKey.Builder(Curve.P_256, (ECPublicKey) kp.getPublic())
                .privateKey((ECPrivateKey) kp.getPrivate());
        if (kid != null) {
            b.keyID(kid);
        }
        return b.build();
    }

    private static String proof(ECKey key, String htm, String htu, String ath) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString()).claim("htm", htm).claim("htu", htu).issueTime(new Date());
        if (ath != null) {
            claims.claim("ath", ath);
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK()).build(), claims.build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static String ath(String accessToken) throws Exception {
        return Base64URL.encode(MessageDigest.getInstance("SHA-256")
                .digest(accessToken.getBytes(StandardCharsets.US_ASCII))).toString();
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
