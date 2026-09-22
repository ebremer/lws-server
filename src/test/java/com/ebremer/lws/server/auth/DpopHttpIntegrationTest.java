package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.ebremer.lws.server.JettyLauncher;
import com.ebremer.lws.server.LwsComponents;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.TestDirs;

/**
 * DPoP (RFC 9449) over a real socket: the {@code Authorization: DPoP} scheme, the {@code DPoP} proof
 * header, and the {@code DPoP-Nonce} challenge, driven end to end through
 * {@link AuthenticationFilter}.
 *
 * <p><b>The gap this closes.</b> Nothing in this suite sent a {@code DPoP} — or a {@code SAML2} —
 * {@code Authorization} header at all. {@link DpopValidatorTest} builds correct proofs and never
 * puts one on the wire; {@link AuthenticationFilterTest} is Mockito-only, never opens a socket, and
 * constructs its own {@link DpopValidator} by hand rather than the one {@code LwsComponents} builds
 * from configuration. So every rule that lives in the filter rather than in the validator — the
 * order the refusals are made in, which scheme each challenge names, whether a header set before
 * {@code sendError} reaches the client, and whether {@code lws.dpop.require-nonce} actually produces
 * a usable nonce — was unexecuted. A resource server that answered {@code use_dpop_nonce} with no
 * {@code DPoP-Nonce} header, or that named {@code Bearer} in the challenge that refuses a Bearer
 * downgrade, would have passed the whole suite.
 *
 * <p><b>What the refusals assert.</b> Every one of the filter's six DPoP refusal steps produces the
 * same {@code 401}, so a status assertion alone cannot tell them apart — a proof rejected for the
 * wrong reason still looks correct. Each test therefore asserts the <em>exact</em>
 * {@code WWW-Authenticate} challenge, which is the only thing that distinguishes them and the only
 * thing a client can act on.
 *
 * <p><b>Two servers.</b> {@code lws.dpop.require-nonce} is read once, when {@code LwsComponents}
 * decides whether to give the {@link DpopValidator} a {@link DpopNonceService}, so the nonce-required
 * posture needs a second server — and, because a TDB2 lock is per-directory, a second
 * {@link TestDirs#create()} directory.
 *
 * @author Erich Bremer
 */
class DpopHttpIntegrationTest {

    /**
     * The two data directories. Deleted on the way out where the platform allows it, and by the next
     * run's sweep where it does not — see {@link TestDirs}.
     */
    private static final Path tempDir = TestDirs.create();
    private static final Path nonceTempDir = TestDirs.create();

    /** The fixture resource every test reads, and the literal that proves the read succeeded. */
    private static final String FIXTURE_NAME = "dpop-fixture";
    private static final String FIXTURE = "<#it> <http://schema.org/name> \"" + FIXTURE_NAME + "\" .";
    private static final String DOC = "/dpop-doc";

    /** The link relation from a Storage Resource — or a refusal — to its storage (lws10-core). */
    private static final String STORAGE_REL = "https://www.w3.org/ns/lws#storage";

    /** The proof algorithms a DPoP challenge lists (RFC 9449 §7.1). */
    private static final String DPOP_ALGS = "ES256 ES384 ES512 EdDSA RS256 RS384 RS512 PS256 PS384 PS512";

    private static HttpClient http;

    /** The ordinary server: DPoP accepted, no nonce required. */
    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;

    /** The same storage with {@code lws.dpop.require-nonce=true}. */
    private static Server nonceServer;
    private static LwsComponents nonceComponents;
    private static String nonceBaseUrl;

    /** The holder key, and a second key the client does not prove possession of. */
    private static ECKey proofKey;
    private static ECKey otherKey;
    private static String jkt;

    /** Credentials. Each is audience-bound to the storage it is used against. */
    private static String setupToken;
    private static String boundToken;
    private static String wrongKeyToken;
    private static String nonceBoundToken;

    @BeforeAll
    static void start() throws Exception {
        http = HttpClient.newHttpClient();

        proofKey = ecKey();
        otherKey = ecKey();
        jkt = proofKey.computeThumbprint().toString();

        AuthTestSupport.Ed ed = AuthTestSupport.ed25519();
        // The did:key IS the WebID in this suite, and it is the configured owner. A request that
        // authenticates is therefore a 200 and not a 403, so every refusal below is unambiguously
        // the DPoP layer refusing rather than authorization declining afterwards.
        String did = AuthTestSupport.didKeyEd25519(ed.publicRaw());

        int port = freePort();
        baseUrl = "http://localhost:" + port;
        LwsConfiguration config = LwsConfiguration.of(properties(baseUrl, tempDir, did, false));
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();

        int noncePort = freePort();
        nonceBaseUrl = "http://localhost:" + noncePort;
        LwsConfiguration nonceConfig =
                LwsConfiguration.of(properties(nonceBaseUrl, nonceTempDir, did, true));
        nonceComponents = LwsComponents.create(nonceConfig);
        nonceServer = new Server(noncePort);
        nonceServer.setHandler(JettyLauncher.buildHandler(nonceComponents, nonceConfig));
        nonceServer.start();

        setupToken = AuthTestSupport.signEdDSA(ed, null, did, did, did, AuthTestSupport.future(), baseUrl);
        boundToken = AuthTestSupport.signEdDSAWithCnf(ed, did, AuthTestSupport.future(), jkt, baseUrl);
        wrongKeyToken = AuthTestSupport.signEdDSAWithCnf(ed, did, AuthTestSupport.future(),
                otherKey.computeThumbprint().toString(), baseUrl);
        nonceBoundToken =
                AuthTestSupport.signEdDSAWithCnf(ed, did, AuthTestSupport.future(), jkt, nonceBaseUrl);

        // The fixture is written with a plain, unbound Bearer credential: a DPoP-bound token could
        // not be used for it without a proof, and neither server sets lws.dpop.require.
        assertEquals(201, writeFixture(baseUrl, setupToken).statusCode(),
                "the fixture every test reads must exist before any of them run");
        String nonceSetupToken =
                AuthTestSupport.signEdDSA(ed, null, did, did, did, AuthTestSupport.future(), nonceBaseUrl);
        assertEquals(201, writeFixture(nonceBaseUrl, nonceSetupToken).statusCode());
    }

    @AfterAll
    static void stop() throws Exception {
        if (server != null) {
            server.stop();
        }
        if (components != null) {
            components.close();
        }
        if (nonceServer != null) {
            nonceServer.stop();
        }
        if (nonceComponents != null) {
            nonceComponents.close();
        }
    }

    // ----- the happy path, which every refusal below is measured against -----

    @Test
    void aValidTokenAndProofAuthenticate() throws Exception {
        HttpResponse<String> r = dpopGet(baseUrl, DOC, boundToken, freshProof(baseUrl, "GET", boundToken));
        assertEquals(200, r.statusCode(), detail(r));
        assertTrue(r.body().contains(FIXTURE_NAME), r.body());
    }

    /**
     * The control for every {@code Bearer} refusal below: an <em>unbound</em> credential under the
     * {@code Bearer} scheme is still honoured, so those refusals are about the binding and the
     * scheme, not about the token or the owner configuration.
     */
    @Test
    void anUnboundCredentialIsStillAcceptedAsABearerToken() throws Exception {
        HttpResponse<String> r = withScheme("Bearer", setupToken);
        assertEquals(200, r.statusCode(), detail(r));
        assertTrue(r.body().contains(FIXTURE_NAME), r.body());
    }

    // ----- the proof has to be for this request -----

    @Test
    void aProofBoundToAnotherPathIsRefused() throws Exception {
        HttpResponse<String> r = dpopGet(baseUrl, DOC, boundToken,
                proof(proofKey, "GET", baseUrl + "/other-doc", jti(), new Date(), ath(boundToken)));
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(dpopChallenge("invalid DPoP proof"), challenge(r));
        assertAdvertisesTheStorageDescription(r);
    }

    /**
     * {@code htm} is part of what the proof covers, so a proof captured from a read cannot be lifted
     * onto a write — and the write it was lifted onto did not happen.
     */
    @Test
    void aProofForAnotherMethodIsRefused() throws Exception {
        HttpResponse<String> r = dpop(baseUrl, "PUT", DOC, boundToken,
                proof(proofKey, "GET", baseUrl + DOC, jti(), new Date(), ath(boundToken)),
                "<#it> <http://schema.org/name> \"overwritten\" .");
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(dpopChallenge("invalid DPoP proof"), challenge(r));

        HttpResponse<String> reread = dpopGet(baseUrl, DOC, boundToken, freshProof(baseUrl, "GET", boundToken));
        assertEquals(200, reread.statusCode(), detail(reread));
        assertTrue(reread.body().contains(FIXTURE_NAME), "a refused write must not have landed: " + reread.body());
    }

    /** {@code ath} binds the proof to one access token; a proof minted for another one is not this one. */
    @Test
    void aProofBoundToADifferentAccessTokenIsRefused() throws Exception {
        HttpResponse<String> r = dpopGet(baseUrl, DOC, boundToken,
                proof(proofKey, "GET", baseUrl + DOC, jti(), new Date(), ath("some-other-access-token")));
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(dpopChallenge("invalid DPoP proof"), challenge(r));
    }

    /** {@code iat} freshness is what keeps a proof from being useful for longer than one request. */
    @Test
    void anExpiredProofIsRefused() throws Exception {
        HttpResponse<String> r = dpopGet(baseUrl, DOC, boundToken,
                proof(proofKey, "GET", baseUrl + DOC, jti(),
                        new Date(System.currentTimeMillis() - 3_600_000L), ath(boundToken)));
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(dpopChallenge("invalid DPoP proof"), challenge(r));
    }

    @Test
    void theDpopSchemeRequiresAProofHeader() throws Exception {
        HttpResponse<String> r = dpopGet(baseUrl, DOC, boundToken, null);
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(dpopChallenge("a DPoP proof header is required"), challenge(r));
        assertAdvertisesTheStorageDescription(r);
    }

    // ----- the token has to be bound to the key the proof demonstrates -----

    /**
     * The proof verifies and the access token validates; only {@code cnf.jkt} disagrees. That is the
     * whole of DPoP: without this check a valid token and any valid proof would authenticate
     * together, and the binding would be decoration.
     */
    @Test
    void aTokenBoundToAnotherKeyIsRefused() throws Exception {
        HttpResponse<String> r = dpopGet(baseUrl, DOC, wrongKeyToken,
                proof(proofKey, "GET", baseUrl + DOC, jti(), new Date(), ath(wrongKeyToken)));
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(dpopChallenge("access token is not bound to the DPoP key"), challenge(r));
    }

    /**
     * The mirror case, and the one an attacker actually has: a captured token presented with a
     * correctly formed proof made by a key they generated themselves.
     */
    @Test
    void aCaptorSubstitutingTheirOwnProofKeyIsRefused() throws Exception {
        HttpResponse<String> r = dpopGet(baseUrl, DOC, boundToken,
                proof(otherKey, "GET", baseUrl + DOC, jti(), new Date(), ath(boundToken)));
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(dpopChallenge("access token is not bound to the DPoP key"), challenge(r));
    }

    // ----- RFC 9449 §7.1: a bound token is never honoured without a proof -----

    /**
     * A {@code cnf.jkt}-bearing token presented as a plain Bearer token is refused, and the challenge
     * names <strong>DPoP</strong> — the scheme the client must switch to, not the one it used. A
     * challenge naming {@code Bearer} would tell the client to retry exactly what just failed.
     */
    @Test
    void aBoundTokenPresentedAsBearerIsRefused() throws Exception {
        HttpResponse<String> r = withScheme("Bearer", boundToken);
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(dpopChallenge(
                "this access token is DPoP-bound and must be presented with the DPoP scheme and a proof"),
                challenge(r));
        assertAdvertisesTheStorageDescription(r);
    }

    /**
     * And the same under {@code SAML2}. The downgrade defence used to be gated on the scheme being
     * {@code Bearer}, while {@code LwsCredentialValidator} routes on the credential's <em>shape</em> —
     * so writing {@code SAML2} in front of a JWT was an unconditional way round it, and a captured
     * bound token was honoured with no proof at all.
     */
    @Test
    void aBoundTokenPresentedUnderTheSaml2SchemeIsRefusedToo() throws Exception {
        HttpResponse<String> r = withScheme("SAML2", boundToken);
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(dpopChallenge(
                "this access token is DPoP-bound and must be presented with the DPoP scheme and a proof"),
                challenge(r));
    }

    /**
     * The scheme has to agree with the credential: {@code SAML2} carries a SAML assertion, and a JWT
     * announced under it is refused even when it is a perfectly valid unbound one — which the
     * {@code Bearer} control above shows it is.
     */
    @Test
    void theSaml2SchemeDoesNotCarryAJwt() throws Exception {
        HttpResponse<String> r = withScheme("SAML2", setupToken);
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals("SAML2 realm=\"" + baseUrl + "/\", error=\"invalid_token\", "
                + "error_description=\"the SAML2 scheme carries a SAML assertion, not a JWT\"",
                challenge(r));
    }

    // ----- replay -----

    @Test
    void aProofCannotBeReplayed() throws Exception {
        String proof = freshProof(baseUrl, "GET", boundToken);
        assertEquals(200, dpopGet(baseUrl, DOC, boundToken, proof).statusCode(),
                "the first use of a valid proof is accepted");

        HttpResponse<String> replay = dpopGet(baseUrl, DOC, boundToken, proof);
        assertEquals(401, replay.statusCode(), detail(replay));
        assertEquals(dpopChallenge("this DPoP proof has already been used"), challenge(replay));
    }

    // ----- lws.dpop.require-nonce (RFC 9449 §8), on the second server -----

    /**
     * A {@code use_dpop_nonce} challenge is only actionable if it carries the nonce, so the header is
     * asserted alongside the challenge: a server that demanded a nonce and never issued one would
     * refuse every DPoP request forever, and would still answer 401 with the right error code.
     */
    @Test
    void aMissingNonceProducesAChallengeCarryingOne() throws Exception {
        HttpResponse<String> r = dpopGet(nonceBaseUrl, DOC, nonceBoundToken,
                freshProof(nonceBaseUrl, "GET", nonceBoundToken));
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(nonceChallenge(), challenge(r));
        assertFalse(r.headers().firstValue("DPoP-Nonce").orElse("").isBlank(),
                "a use_dpop_nonce challenge with no DPoP-Nonce header cannot be retried");
        assertAdvertisesTheStorageDescription(r);
    }

    @Test
    void theChallengedNonceMakesTheRetrySucceed() throws Exception {
        String nonce = nonceFromChallenge(jti());

        HttpResponse<String> retry = dpopGet(nonceBaseUrl, DOC, nonceBoundToken,
                proofWithNonce(proofKey, "GET", nonceBaseUrl + DOC, jti(), new Date(),
                        ath(nonceBoundToken), nonce));
        assertEquals(200, retry.statusCode(), detail(retry));
        assertTrue(retry.body().contains(FIXTURE_NAME), retry.body());
    }

    /**
     * Only a nonce this server minted counts. Tampering with one character of a genuine nonce breaks
     * its HMAC, and the request is challenged again rather than admitted — otherwise the client would
     * simply invent its own nonce and the whole mechanism would be a formality.
     */
    @Test
    void aNonceTheServerNeverIssuedIsRefused() throws Exception {
        String nonce = nonceFromChallenge(jti());
        int dot = nonce.indexOf('.');
        String mac = nonce.substring(dot + 1);
        // The first character of the MAC segment, not the last: base64url encodes 32 bytes in 43
        // characters, so the final character's two low bits are padding and a decoder is free to
        // ignore them — flipping one of those would leave the nonce byte-for-byte valid.
        String tampered = nonce.substring(0, dot + 1)
                + (mac.charAt(0) == 'A' ? 'B' : 'A') + mac.substring(1);

        HttpResponse<String> r = dpopGet(nonceBaseUrl, DOC, nonceBoundToken,
                proofWithNonce(proofKey, "GET", nonceBaseUrl + DOC, jti(), new Date(),
                        ath(nonceBoundToken), tampered));
        assertEquals(401, r.statusCode(), detail(r));
        assertEquals(nonceChallenge(), challenge(r));
    }

    /**
     * A request refused at the nonce stage must not have consumed its {@code jti} (finding M6):
     * {@code claimProof} runs last, after the access token has validated and is confirmed bound, so
     * the retry may reuse the very proof identifier the challenged attempt carried.
     *
     * <p>If the {@code jti} were claimed during verification instead, the mandatory first round trip
     * of every nonce-mode exchange would burn it and the retry would be refused as a replay — DPoP
     * with nonces would not work at all, and no other test in this class would notice, because each
     * of them mints a fresh one.
     */
    @Test
    void theRejectedAttemptDidNotBurnItsJti() throws Exception {
        String jti = jti();
        String nonce = nonceFromChallenge(jti);

        HttpResponse<String> retry = dpopGet(nonceBaseUrl, DOC, nonceBoundToken,
                proofWithNonce(proofKey, "GET", nonceBaseUrl + DOC, jti, new Date(),
                        ath(nonceBoundToken), nonce));
        assertEquals(200, retry.statusCode(),
                "the challenged attempt must not have consumed the jti the retry reuses: " + detail(retry));
    }

    // ----- request helpers -----

    private static Properties properties(String base, Path dataDir, String ownerDid, boolean requireNonce) {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", base);
        p.setProperty("lws.data-dir", dataDir.toString());
        p.setProperty("lws.owners", ownerDid);
        p.setProperty("lws.public-read", "false");
        if (requireNonce) {
            p.setProperty("lws.dpop.require-nonce", "true");
        }
        return p;
    }

    private static HttpResponse<String> writeFixture(String base, String bearerToken) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base + DOC))
                .header("Content-Type", "text/turtle")
                .header("Authorization", "Bearer " + bearerToken)
                .PUT(HttpRequest.BodyPublishers.ofString(FIXTURE)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /** A GET of {@link #DOC} under the given scheme, for the RFC 9449 §7.1 downgrade cases. */
    private static HttpResponse<String> withScheme(String scheme, String credential) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(baseUrl + DOC))
                .header("Accept", "text/turtle")
                .header("Authorization", scheme + " " + credential)
                .GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> dpopGet(String base, String path, String accessToken, String proof)
            throws Exception {
        return dpop(base, "GET", path, accessToken, proof, null);
    }

    /** A request under the DPoP scheme; a null {@code proof} omits the {@code DPoP} header entirely. */
    private static HttpResponse<String> dpop(String base, String method, String path, String accessToken,
            String proof, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
                .header("Accept", "text/turtle")
                .header("Authorization", "DPoP " + accessToken);
        if (proof != null) {
            b.header("DPoP", proof);
        }
        if (body != null) {
            b.header("Content-Type", "text/turtle");
        }
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Drive one nonce-less attempt against the nonce-required server and return the nonce it hands
     * back, using {@code jti} for the proof so a caller can check whether that identifier survived.
     */
    private static String nonceFromChallenge(String jti) throws Exception {
        HttpResponse<String> challenged = dpopGet(nonceBaseUrl, DOC, nonceBoundToken,
                proof(proofKey, "GET", nonceBaseUrl + DOC, jti, new Date(), ath(nonceBoundToken)));
        assertEquals(401, challenged.statusCode(), detail(challenged));
        return challenged.headers().firstValue("DPoP-Nonce")
                .orElseThrow(() -> new AssertionError("the challenge carried no DPoP-Nonce to retry with"));
    }

    // ----- assertion helpers -----

    private static String challenge(HttpResponse<String> response) {
        return response.headers().firstValue("WWW-Authenticate").orElseThrow(() -> new AssertionError(
                "a 401 must tell the client how to authenticate, but carried no WWW-Authenticate"));
    }

    /**
     * The challenge {@code AuthenticationFilter.unauthorized} builds for the DPoP scheme: the
     * lws10-core shape — the authorization server to get a token from ({@code as_uri}) and the
     * storage as {@code realm} — plus the proof algorithms, the error and its description.
     */
    private static String dpopChallenge(String description) {
        return dpopChallenge(baseUrl, "invalid_token", description);
    }

    private static String dpopChallenge(String base, String error, String description) {
        return "DPoP as_uri=\"" + base + "\", realm=\"" + base + "/\", algs=\"" + DPOP_ALGS
                + "\", error=\"" + error + "\", error_description=\"" + description + "\"";
    }

    /** The challenge {@code AuthenticationFilter.dpopNonceChallenge} builds, on the nonce server. */
    private static String nonceChallenge() {
        return dpopChallenge(nonceBaseUrl, "use_dpop_nonce", "a nonce is required in the DPoP proof");
    }

    /**
     * A refusal still has to be discoverable: the client is pointed at the storage, whose URI
     * dereferences to the storage description, so it can find out how to authenticate. These headers
     * are set before {@code sendError}, which is the part worth pinning — a servlet container that
     * dropped them would leave the challenge unusable.
     */
    private static void assertAdvertisesTheStorageDescription(HttpResponse<String> response) {
        assertTrue(response.headers().allValues("Link").stream()
                        .anyMatch(l -> l.contains("rel=\"" + STORAGE_REL + "\"")),
                "a refused request must still link to the storage: "
                        + response.headers().allValues("Link"));
    }

    /** The most informative thing a failed status assertion can say: the challenge, or the body. */
    private static String detail(HttpResponse<String> response) {
        return response.headers().firstValue("WWW-Authenticate").orElseGet(response::body);
    }

    // ----- proof construction (the shapes DpopValidatorTest verifies at unit level) -----

    /** A well-formed proof for {@code base + DOC}, with a {@code jti} no other request has used. */
    private static String freshProof(String base, String htm, String accessToken) throws Exception {
        return proof(proofKey, htm, base + DOC, jti(), new Date(), ath(accessToken));
    }

    private static String jti() {
        return UUID.randomUUID().toString();
    }

    private static ECKey ecKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        return new ECKey.Builder(Curve.P_256, (ECPublicKey) kp.getPublic())
                .privateKey((ECPrivateKey) kp.getPrivate()).build();
    }

    private static String proof(ECKey key, String htm, String htu, String jti, Date iat, String ath)
            throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(key.toPublicJWK())
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(jti).claim("htm", htm).claim("htu", htu).issueTime(iat).claim("ath", ath).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static String proofWithNonce(ECKey key, String htm, String htu, String jti, Date iat,
            String ath, String nonce) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK()).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().jwtID(jti).claim("htm", htm).claim("htu", htu)
                .issueTime(iat).claim("ath", ath).claim("nonce", nonce).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    /** {@code ath}: the base64url SHA-256 of the access token, which binds the proof to it. */
    private static String ath(String accessToken) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(accessToken.getBytes("US-ASCII"));
        return Base64URL.encode(digest).toString();
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
