package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Tests the self-signed controlled identifier suite (lws10-authn-ssi-cid): a JWT verified with the
 * verification method its {@code kid} names in the subject's controlled identifier document,
 * retrieved as CID 1.0 §3.3 describes — and, since the self-signed did:key suite was discontinued in
 * its favour, for {@code did:key} and {@code did:web} subjects as well as HTTPS ones.
 *
 * @author Erich Bremer
 */
class SsiCidValidatorTest {

    private static final String SUB = "https://alice.example/cid";
    private static final String KID = SUB + "#key-1";
    private static final String STORAGE = "https://storage.example";

    private final AuthTestSupport.Ed key = AuthTestSupport.ed25519();

    /** The suite's own example shape: the method defined once, referenced from authentication. */
    private final String cidDocument = "{\"@context\":[\"https://www.w3.org/ns/cid/v1\"],\"id\":\"" + SUB + "\","
            + "\"verificationMethod\":[" + method(KID, "JsonWebKey", SUB, "") + "],"
            + "\"authentication\":[\"" + KID + "\"]}";

    private final DocumentLoader resolver = url -> SUB.equals(url) ? cidDocument : null;
    private final SsiCidValidator validator =
            new SsiCidValidator(resolver, AudiencePolicy.permitAll(), 0);
    /** A storage that binds credentials to itself and caps self-minted token lifetimes at an hour. */
    private final SsiCidValidator strict =
            new SsiCidValidator(resolver, new AudiencePolicy(Set.of(STORAGE), true), 3_600_000L);

    private String method(String id, String type, String controller, String extra) {
        return "{\"id\":\"" + id + "\",\"type\":\"" + type + "\",\"controller\":\"" + controller + "\","
                + "\"publicKeyJwk\":" + key.publicJwk().toJSONString() + extra + "}";
    }

    private SsiCidValidator over(String document) {
        return new SsiCidValidator(url -> SUB.equals(url) ? document : null, AudiencePolicy.permitAll(), 0);
    }

    private String token(String kid) {
        return AuthTestSupport.signEdDSA(key, kid, SUB, SUB, SUB, AuthTestSupport.future());
    }

    @Test
    void acceptsValidSelfIssuedCredential() throws Exception {
        Optional<LwsPrincipal> principal = validator.validate(token(KID));
        assertTrue(principal.isPresent());
        assertEquals(SUB, principal.get().webId());
    }

    /** The {@code kid} may also be the method's fragment, with or without its {@code #}. */
    @Test
    void selectsTheMethodByFragmentToo() throws Exception {
        assertTrue(validator.validate(token("key-1")).isPresent());
        assertTrue(validator.validate(token("#key-1")).isPresent());
    }

    /** The suite's own example embeds the method in {@code authentication} rather than referencing it. */
    @Test
    void acceptsAMethodEmbeddedInAuthentication() throws Exception {
        String embedded = "{\"id\":\"" + SUB + "\",\"authentication\":[" + method(KID, "JsonWebKey", SUB, "") + "]}";
        assertTrue(over(embedded).validate(token(KID)).isPresent());
    }

    /**
     * CID 1.0 §2.3: a method not associated with the {@code authentication} relationship cannot be
     * used for it. This server used to accept any method with a matching {@code kid}.
     */
    @Test
    void refusesAMethodTheAuthenticationRelationshipDoesNotName() throws Exception {
        String listedOnly = "{\"id\":\"" + SUB + "\",\"verificationMethod\":[" + method(KID, "JsonWebKey", SUB, "") + "],"
                + "\"assertionMethod\":[\"" + KID + "\"]}";
        assertTrue(over(listedOnly).validate(token(KID)).isEmpty());
    }

    @Test
    void refusesAMethodControlledBySomeoneElse() throws Exception {
        String foreign = "{\"id\":\"" + SUB + "\",\"authentication\":["
                + method(KID, "JsonWebKey", "https://mallory.example/cid", "") + "]}";
        assertTrue(over(foreign).validate(token(KID)).isEmpty());
    }

    @Test
    void refusesADocumentAboutAnotherSubject() throws Exception {
        String other = cidDocument.replace("\"id\":\"" + SUB + "\",\"verificationMethod\"",
                "\"id\":\"https://bob.example/cid\",\"verificationMethod\"");
        assertTrue(over(other).validate(token(KID)).isEmpty());
    }

    @Test
    void refusesRevokedAndExpiredMethods() throws Exception {
        String past = Instant.now().minusSeconds(60).toString();
        String revoked = "{\"id\":\"" + SUB + "\",\"authentication\":["
                + method(KID, "JsonWebKey", SUB, ",\"revoked\":\"" + past + "\"") + "]}";
        String expired = "{\"id\":\"" + SUB + "\",\"authentication\":["
                + method(KID, "JsonWebKey", SUB, ",\"expires\":\"" + past + "\"") + "]}";
        String later = "{\"id\":\"" + SUB + "\",\"authentication\":["
                + method(KID, "JsonWebKey", SUB, ",\"expires\":\"" + Instant.now().plusSeconds(3600) + "\"") + "]}";
        assertTrue(over(revoked).validate(token(KID)).isEmpty(), "revoked");
        assertTrue(over(expired).validate(token(KID)).isEmpty(), "expired");
        assertTrue(over(later).validate(token(KID)).isPresent(), "not yet expired");
    }

    /** CID 1.0 §2.2.3: a publicKeyJwk MUST NOT carry private members; such a key is compromised. */
    @Test
    void refusesAPublishedPrivateKey() throws Exception {
        String leaked = "{\"id\":\"" + SUB + "\",\"authentication\":["
                + method(KID, "JsonWebKey", SUB, "").replace("\"kty\":", "\"d\":\"AAAA\",\"kty\":") + "]}";
        assertTrue(over(leaked).validate(token(KID)).isEmpty());
    }

    /** The Security Vocabulary's predecessor of JsonWebKey is read the same way. */
    @Test
    void readsJsonWebKey2020AsJsonWebKey() throws Exception {
        String legacy = "{\"id\":\"" + SUB + "\",\"authentication\":[" + method(KID, "JsonWebKey2020", SUB, "") + "]}";
        assertTrue(over(legacy).validate(token(KID)).isPresent());
    }

    @Test
    void readsAMultikeyMethod() throws Exception {
        String multibase = AuthTestSupport.didKeyEd25519(key.publicRaw()).substring("did:key:".length());
        String doc = "{\"id\":\"" + SUB + "\",\"authentication\":[{\"id\":\"" + KID + "\",\"type\":\"Multikey\","
                + "\"controller\":\"" + SUB + "\",\"publicKeyMultibase\":\"" + multibase + "\"}]}";
        assertTrue(over(doc).validate(token(KID)).isPresent());
    }

    /**
     * A did:key subject resolves locally to its DID document; the {@code kid} names its one
     * verification method, {@code <did>#<multibase>} — the generalization the discontinued did:key
     * suite was folded into.
     */
    @Test
    void acceptsADidKeySubject() throws Exception {
        String did = AuthTestSupport.didKeyEd25519(key.publicRaw());
        String kid = did + "#" + did.substring("did:key:".length());
        SsiCidValidator nothingToFetch = new SsiCidValidator(url -> null, AudiencePolicy.permitAll(), 0);
        String credential = AuthTestSupport.signEdDSA(key, kid, did, did, did, AuthTestSupport.future());
        assertEquals(did, nothingToFetch.validate(credential).orElseThrow().webId());

        AuthTestSupport.Ed other = AuthTestSupport.ed25519();
        String forged = AuthTestSupport.signEdDSA(other, kid, did, did, did, AuthTestSupport.future());
        assertTrue(nothingToFetch.validate(forged).isEmpty(), "signed by a key that is not the did:key's");
        String noKid = AuthTestSupport.signEdDSA(key, null, did, did, did, AuthTestSupport.future());
        assertTrue(nothingToFetch.validate(noKid).isEmpty(), "the suite requires a kid");
    }

    /** A did:web subject is fetched from the HTTPS URL its method derives — never from the DID itself. */
    @Test
    void resolvesADidWebSubjectOverHttps() throws Exception {
        String did = "did:web:alice.example:people:alice";
        String kid = did + "#key-1";
        String doc = "{\"id\":\"" + did + "\",\"verificationMethod\":[{\"id\":\"" + kid + "\",\"type\":\"JsonWebKey\","
                + "\"controller\":\"" + did + "\",\"publicKeyJwk\":" + key.publicJwk().toJSONString() + "}],"
                + "\"authentication\":[\"#key-1\"]}";
        java.util.List<String> fetched = new java.util.ArrayList<>();
        SsiCidValidator web = new SsiCidValidator(url -> {
            fetched.add(url);
            return url.equals("https://alice.example/people/alice/did.json") ? doc : null;
        }, AudiencePolicy.permitAll(), 0);
        String credential = AuthTestSupport.signEdDSA(key, kid, did, did, did, AuthTestSupport.future());
        assertEquals(did, web.validate(credential).orElseThrow().webId());
        assertEquals(java.util.List.of("https://alice.example/people/alice/did.json"), fetched);
    }

    @Test
    void refusesDidMethodsItCannotResolve() throws Exception {
        String did = "did:example:123456789abcdefghi";
        String credential = AuthTestSupport.signEdDSA(key, did + "#k", did, did, did, AuthTestSupport.future());
        assertTrue(validator.validate(credential).isEmpty());
    }

    @Test
    void rejectsUnknownKidMissingDocExpiredAndForged() throws Exception {
        // kid not present in the CID document
        assertTrue(validator.validate(token(SUB + "#other")).isEmpty());
        // document cannot be dereferenced
        SsiCidValidator noDoc = new SsiCidValidator(url -> null, AudiencePolicy.permitAll(), 0);
        assertTrue(noDoc.validate(token(KID)).isEmpty());
        // expired
        assertTrue(validator.validate(
                AuthTestSupport.signEdDSA(key, KID, SUB, SUB, SUB, AuthTestSupport.past())).isEmpty());
        // forged: signed by a different key but claiming the same subject/kid
        AuthTestSupport.Ed forger = AuthTestSupport.ed25519();
        assertTrue(validator.validate(
                AuthTestSupport.signEdDSA(forger, KID, SUB, SUB, SUB, AuthTestSupport.future()))
                .isEmpty());
    }

    /**
     * A self-signed credential is minted by its holder, so nothing but the {@code aud} claim ties
     * it to one storage. Without the check, the token a user presents to storage A is replayable
     * verbatim against storage B.
     */
    @Test
    void rejectsCredentialAddressedToAnotherStorage() throws Exception {
        String forOther = AuthTestSupport.signEdDSA(
                key, KID, SUB, SUB, SUB, AuthTestSupport.future(), "https://other-storage.example");
        assertTrue(strict.validate(forOther).isEmpty(),
                "a credential whose aud names another storage must be rejected");

        String forUs = AuthTestSupport.signEdDSA(
                key, KID, SUB, SUB, SUB, AuthTestSupport.future(), STORAGE);
        assertTrue(strict.validate(forUs).isPresent(), "a credential addressed to this storage is accepted");
    }

    @Test
    void rejectsCredentialWithNoAudienceWhenRequired() throws Exception {
        assertTrue(strict.validate(token(KID)).isEmpty(),
                "a credential with no aud must be rejected when one is required");
    }

    /** An unbounded expiry turns a single leak into a permanent, unrevocable credential. */
    @Test
    void rejectsCredentialClaimingACenturyOfValidity() throws Exception {
        String forever = AuthTestSupport.signEdDSA(
                key, KID, SUB, SUB, SUB, AuthTestSupport.farFuture(), STORAGE);
        assertTrue(strict.validate(forever).isEmpty(),
                "a self-minted token claiming a 100-year lifetime must be rejected");
    }
}
