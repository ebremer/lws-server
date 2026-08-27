package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Tests the SAML 2.0 suite: a signed assertion is accepted only when signed by a trusted key,
 * from a trusted issuer, and untampered — and only when the signature that verified is the one
 * covering the very assertion whose claims are read.
 *
 * <p>The second half of this class is an XML Signature Wrapping battery (finding C1). Every case
 * relocates a <em>genuine, untouched</em> signed assertion into a document that also carries claims
 * the attacker chose, which is exactly what the older {@code rejectsTamperedAssertion} test cannot
 * catch: that one edits signed bytes, so the digest fails for the ordinary reason. Run against the
 * pre-fix validator, four of the seven pass authentication — three as
 * {@code https://attacker.example/profile#me} and one as the genuine subject. The other three are
 * regression pins rather than reproductions: they were already refused, but only incidentally, by a
 * JDK default rather than by anything this class asserted.
 *
 * <p>The last band covers the {@code saml:Conditions} validity window (finding M40). Every fixture
 * in this class used to short-circuit that check — most emit no {@code Conditions} at all, and the
 * audience fixtures emit one with no times — so an expired or not-yet-valid assertion was accepted
 * by code no test had ever executed. The window cases are always paired with a control inside the
 * window, so a refusal has to come from the times and not from the element's mere presence.
 *
 * @author Erich Bremer
 */
class SamlValidatorTest {

    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ISSUER = "https://idp.example";
    private static final String NAME_ID = "https://alice.example/profile#me";
    private static final String EVIL_NAME_ID = "https://attacker.example/profile#me";
    private static final String AUDIENCE = "https://storage.example";

    @Test
    void acceptsAssertionSignedByTrustedKey() throws Exception {
        KeyPair idp = rsa();
        String xml = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);

        Optional<LwsPrincipal> principal = validator.validate(xml);
        assertTrue(principal.isPresent());
        assertEquals(NAME_ID, principal.get().webId());
        assertEquals(ISSUER, principal.get().issuer());
        assertEquals("https://client.example", principal.get().clientId());
    }

    @Test
    void acceptsBase64EncodedAssertion() throws Exception {
        KeyPair idp = rsa();
        String xml = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);
        String base64 = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(), null);
        assertTrue(validator.validate(base64).isPresent());
    }

    @Test
    void rejectsUntrustedKey() throws Exception {
        KeyPair idp = rsa();
        KeyPair other = rsa();
        String xml = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);
        SamlValidator validator = new SamlValidator(List.of(other.getPublic()), Set.of(), null);
        assertTrue(validator.validate(xml).isEmpty());
    }

    @Test
    void rejectsUntrustedIssuer() throws Exception {
        KeyPair idp = rsa();
        String xml = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of("https://other-idp"), null);
        assertTrue(validator.validate(xml).isEmpty());
    }

    @Test
    void rejectsTamperedAssertion() throws Exception {
        KeyPair idp = rsa();
        String xml = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);
        String tampered = xml.replace(NAME_ID, "https://evil.example/me");
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(), null);
        assertTrue(validator.validate(tampered).isEmpty());
    }

    // ----- C1: XML Signature Wrapping -----

    /**
     * The original attack: the genuine assertion, still signed and still verifying, is re-parented
     * into a {@code saml:Advice} under an unsigned wrapper carrying the attacker's NameID. The old
     * code picked the claims-bearing element by document order and validated signatures anywhere in
     * the document, so the two were never the same element.
     */
    @Test
    void rejectsGenuineAssertionWrappedInAdvice() throws Exception {
        KeyPair idp = rsa();
        String genuine = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);

        Document doc = newDocument();
        Element outer = assertionElement(doc, "_evil", ISSUER, EVIL_NAME_ID);
        doc.appendChild(outer);
        Element advice = doc.createElementNS(SAML_NS, "saml:Advice");
        outer.appendChild(advice);
        advice.appendChild(importRoot(doc, genuine));

        assertRejected(idp, serialize(doc));
    }

    /** A forged assertion placed ahead of the genuine one, both inside a {@code samlp:Response}. */
    @Test
    void rejectsForgedSiblingOfASignedAssertion() throws Exception {
        KeyPair idp = rsa();
        String genuine = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);

        Document doc = newDocument();
        Element response = responseElement(doc, "_r1");
        doc.appendChild(response);
        response.appendChild(assertionElement(doc, "_evil", ISSUER, EVIL_NAME_ID));
        response.appendChild(importRoot(doc, genuine));

        assertRejected(idp, serialize(doc));
    }

    /**
     * The sharpest case: no assertion is signed at all. The signature covers the enclosing
     * {@code samlp:Response}, which the old code was happy to validate because it scanned the whole
     * document for any signature that verified.
     */
    @Test
    void rejectsSignatureOverANonAssertionElement() throws Exception {
        KeyPair idp = rsa();

        Document doc = newDocument();
        Element response = responseElement(doc, "_r1");
        doc.appendChild(response);
        response.appendChild(assertionElement(doc, "_evil", ISSUER, EVIL_NAME_ID));
        signEnveloped(response, idp.getPrivate(), "#_r1");

        assertRejected(idp, serialize(doc));
    }

    /**
     * The genuine signature is detached and re-parented onto the attacker's assertion, so it sits
     * where a valid signature would and the document carries exactly one of each. Two things then
     * refuse it: its {@code Reference} names {@code #_a1} while the assertion it now hangs from is
     * {@code _evil}, and — because only the used assertion's {@code ID} is marked — {@code #_a1}
     * no longer resolves to anything at all, so the digest cannot even be recomputed.
     */
    @Test
    void rejectsSignatureRelocatedOntoAForgedAssertion() throws Exception {
        KeyPair idp = rsa();
        String genuine = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);

        Document doc = newDocument();
        Element forged = assertionElement(doc, "_evil", ISSUER, EVIL_NAME_ID);
        doc.appendChild(forged);
        Element genuineRoot = importRoot(doc, genuine);
        forged.appendChild(signatureOf(genuineRoot));

        assertRejected(idp, serialize(doc));
    }

    /**
     * A whole-document signature ({@code Reference URI=""}). It verifies, but it says nothing about
     * which of the document's elements is the assertion, so SAML Core §5.4.2's requirement that the
     * reference name the assertion is what makes the binding meaningful. Accepted before the fix.
     */
    @Test
    void rejectsWholeDocumentSignature() throws Exception {
        KeyPair idp = rsa();

        Document doc = newDocument();
        Element assertion = assertionElement(doc, "_a1", ISSUER, NAME_ID);
        doc.appendChild(assertion);
        signEnveloped(assertion, idp.getPrivate(), "");

        assertRejected(idp, serialize(doc));
    }

    /**
     * Two signatures over the same assertion. Harmless in itself, but "some signature in this
     * document verified" is precisely the reasoning that made wrapping possible, so a document that
     * cannot say which signature is <em>the</em> signature is refused.
     */
    @Test
    void rejectsDocumentCarryingMoreThanOneSignature() throws Exception {
        KeyPair idp = rsa();
        String genuine = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);

        Document doc = newDocument();
        Element assertion = importRoot(doc, genuine);
        doc.appendChild(assertion);
        assertion.appendChild(signatureOf(assertion).cloneNode(true));

        assertRejected(idp, serialize(doc));
    }

    /** A wrapper that reuses the genuine assertion's ID, so which element a reference names is ambiguous. */
    @Test
    void rejectsAnIdSharedWithAnotherElement() throws Exception {
        KeyPair idp = rsa();
        String genuine = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);

        Document doc = newDocument();
        Element response = responseElement(doc, "_a1"); // same ID as the genuine assertion
        doc.appendChild(response);
        response.appendChild(importRoot(doc, genuine));

        assertRejected(idp, serialize(doc));
    }

    // ----- C1 companions: claim attribution, transform chain, audience -----

    /**
     * SAML Core lets a {@code SubjectConfirmation} carry its own {@code NameID} — the confirming
     * party, not the subject. One properly signed assertion with that element ahead of the
     * subject's own identifier is enough to mis-attribute the claim if the reader searches
     * descendants by document order instead of walking direct children (finding M1). No crypto is
     * involved, so none of the wrapping checks above catch it.
     */
    @Test
    void readsTheSubjectsOwnNameIdNotAConfirmingPartysNameId() throws Exception {
        KeyPair idp = rsa();

        Document doc = newDocument();
        Element assertion = doc.createElementNS(SAML_NS, "saml:Assertion");
        assertion.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:saml", SAML_NS);
        assertion.setAttribute("ID", "_a1");
        assertion.setAttribute("Version", "2.0");
        assertion.setAttribute("IssueInstant", Instant.now().toString());
        doc.appendChild(assertion);
        Element issuerEl = doc.createElementNS(SAML_NS, "saml:Issuer");
        issuerEl.setTextContent(ISSUER);
        assertion.appendChild(issuerEl);
        Element subject = doc.createElementNS(SAML_NS, "saml:Subject");
        assertion.appendChild(subject);
        // The confirming party's NameID comes first in document order, deliberately.
        Element sc = doc.createElementNS(SAML_NS, "saml:SubjectConfirmation");
        sc.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");
        subject.appendChild(sc);
        Element confirmingParty = doc.createElementNS(SAML_NS, "saml:NameID");
        confirmingParty.setTextContent(EVIL_NAME_ID);
        sc.appendChild(confirmingParty);
        Element scd = doc.createElementNS(SAML_NS, "saml:SubjectConfirmationData");
        scd.setAttribute("Recipient", "https://client.example");
        sc.appendChild(scd);
        Element nameIdEl = doc.createElementNS(SAML_NS, "saml:NameID");
        nameIdEl.setTextContent(NAME_ID);
        subject.appendChild(nameIdEl);
        signEnveloped(assertion, idp.getPrivate(), "#_a1");

        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);
        Optional<LwsPrincipal> principal = validator.validate(serialize(doc));
        assertTrue(principal.isPresent());
        assertEquals(NAME_ID, principal.get().webId());
    }

    /**
     * An XPath transform can select a node-set unrelated to the element the reference names, which
     * decouples what was digested from what the URI claims. The JDK's own secure validation rejects
     * XSLT but permits both XPath dialects, so only the transform allow-list refuses this.
     */
    @Test
    void rejectsATransformChainCarryingAnXPathTransform() throws Exception {
        KeyPair idp = rsa();
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        Document doc = newDocument();
        Element assertion = assertionElement(doc, "_a1", ISSUER, NAME_ID);
        doc.appendChild(assertion);
        signEnveloped(assertion, idp.getPrivate(), "#_a1", List.of(
                fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                fac.newTransform(Transform.XPATH, new XPathFilterParameterSpec("//. | //@* | //namespace::*")),
                fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)));

        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);
        assertTrue(validator.validate(serialize(doc)).isEmpty());
    }

    /**
     * Several {@code AudienceRestriction} elements are a conjunction (SAML Core §2.5.1.4): each is
     * evaluated independently and all must admit us. An assertion the IdP restricted to us
     * <em>and</em> to somebody else is not an assertion for us.
     */
    @Test
    void rejectsAnAssertionAlsoRestrictedToAnotherAudience() throws Exception {
        KeyPair idp = rsa();
        String xml = audienceRestrictedAssertion(idp.getPrivate(),
                List.of(List.of(AUDIENCE), List.of("https://other.example")));
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), AUDIENCE);
        assertTrue(validator.validate(xml).isEmpty());
    }

    /** Within one restriction the audiences are a disjunction, so being listed among them is enough. */
    @Test
    void acceptsAnAssertionListingUsAmongTheAudiencesOfOneRestriction() throws Exception {
        KeyPair idp = rsa();
        String xml = audienceRestrictedAssertion(idp.getPrivate(),
                List.of(List.of("https://other.example", AUDIENCE)));
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), AUDIENCE);
        assertTrue(validator.validate(xml).isPresent());
    }

    /** Configuring an audience means requiring one, not merely checking it when present. */
    @Test
    void rejectsAnUnrestrictedAssertionWhenAnAudienceIsConfigured() throws Exception {
        KeyPair idp = rsa();
        String xml = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID); // no Conditions at all
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), AUDIENCE);
        assertTrue(validator.validate(xml).isEmpty());
        // ... and the same credential is still fine for a deployment that configures no audience.
        assertTrue(new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null).validate(xml).isPresent());
    }

    // ----- M40: the Conditions validity window -----

    /** An assertion whose window opens ten minutes from now is not a credential yet. */
    @Test
    void rejectsAnAssertionThatIsNotYetValid() throws Exception {
        KeyPair idp = rsa();
        String xml = timeConditionedAssertion(idp.getPrivate(), Instant.now().plusSeconds(600), null);
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);
        assertTrue(validator.validate(xml).isEmpty());
    }

    /** An assertion whose window closed ten minutes ago is not a credential any more. */
    @Test
    void rejectsAnExpiredAssertion() throws Exception {
        KeyPair idp = rsa();
        String xml = timeConditionedAssertion(idp.getPrivate(), null, Instant.now().minusSeconds(600));
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);
        assertTrue(validator.validate(xml).isEmpty());
    }

    /**
     * The control for the two above: the same fixture shape, signed the same way, differing only in
     * where the window sits. Without it either refusal could be coming from the mere presence of a
     * {@code Conditions} element rather than from the times it carries.
     */
    @Test
    void acceptsAnAssertionInsideItsValidityWindow() throws Exception {
        KeyPair idp = rsa();
        Instant now = Instant.now();
        String xml = timeConditionedAssertion(idp.getPrivate(),
                now.minusSeconds(300), now.plusSeconds(300));
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);
        Optional<LwsPrincipal> principal = validator.validate(xml);
        assertTrue(principal.isPresent());
        assertEquals(NAME_ID, principal.get().webId());
    }

    /**
     * Both bounds are widened by {@link JwsSupport#CLOCK_SKEW_MS}, so an assertion that misses its
     * window by less than the skew is still honoured — the IdP's clock and ours are not the same
     * clock. These are the assertions that fail if anyone "tidies up" the skew terms away.
     */
    @Test
    void theValidityWindowToleratesTheConfiguredClockSkew() throws Exception {
        KeyPair idp = rsa();
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);

        Instant now = Instant.now();
        assertTrue(validator.validate(timeConditionedAssertion(idp.getPrivate(),
                now.plusMillis(JwsSupport.CLOCK_SKEW_MS / 2), null)).isPresent(),
                "a window opening within the skew must be treated as already open");
        assertTrue(validator.validate(timeConditionedAssertion(idp.getPrivate(),
                null, now.minusMillis(JwsSupport.CLOCK_SKEW_MS / 2))).isPresent(),
                "a window closed within the skew must be treated as still open");
    }

    /**
     * The far side of the same boundary, and what stops the skew from silently growing: five
     * seconds past the end of the skew band the assertion is refused. {@code NotOnOrAfter} is
     * exclusive — the comparison is {@code <=}, so the instant itself is already outside the
     * window — and the five-second margin keeps the case out of the flakiness band.
     */
    @Test
    void theWindowIsExclusiveAtNotOnOrAfter() throws Exception {
        KeyPair idp = rsa();
        String xml = timeConditionedAssertion(idp.getPrivate(), null,
                Instant.now().minusMillis(JwsSupport.CLOCK_SKEW_MS + 5_000));
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);
        assertTrue(validator.validate(xml).isEmpty());
    }

    /**
     * Fail closed: a {@code NotOnOrAfter} the server cannot parse must not be treated as absent.
     * {@code Instant.parse} throws, {@code validate}'s outer catch turns that into a refusal, and
     * the alternative — skipping an attribute that could not be read — would let an IdP's malformed
     * or an attacker's mangled timestamp buy an unbounded credential.
     */
    @Test
    void anUnparseableConditionsTimeIsRefusedRatherThanIgnored() throws Exception {
        KeyPair idp = rsa();
        String xml = timeConditionedAssertionRaw(idp.getPrivate(), null, "not-a-date");
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);
        assertTrue(validator.validate(xml).isEmpty());
    }

    /**
     * The two deliberate accept branches of the window check, pinned so the cases above cannot be
     * "strengthened" into requiring a window. SAML does not oblige an IdP to bound an assertion in
     * time, and an absent attribute reads back as {@code ""} rather than null, so both a missing
     * {@code Conditions} and one carrying no times at all mean "unbounded", not "invalid".
     */
    @Test
    void anAssertionWithNoTimeConditionsIsAccepted() throws Exception {
        KeyPair idp = rsa();
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);
        assertTrue(validator.validate(signedAssertion(idp.getPrivate(), ISSUER, NAME_ID)).isPresent(),
                "an assertion with no Conditions element at all is unbounded, not invalid");
        assertTrue(validator.validate(
                timeConditionedAssertionRaw(idp.getPrivate(), null, null)).isPresent(),
                "a Conditions element carrying neither NotBefore nor NotOnOrAfter is unbounded too");
    }

    /**
     * A single signed assertion enclosed in an unsigned {@code samlp:Response} is the commonest
     * real IdP output and stays accepted: the signature still binds the assertion, and every claim
     * is read from the assertion by direct-child traversal. Pinned so the wrapping checks are not
     * "strengthened" into a root-element rule that would break it for no gain.
     */
    @Test
    void acceptsASignedAssertionEnclosedInAnUnsignedResponse() throws Exception {
        KeyPair idp = rsa();
        String genuine = signedAssertion(idp.getPrivate(), ISSUER, NAME_ID);

        Document doc = newDocument();
        Element response = responseElement(doc, "_r1");
        doc.appendChild(response);
        response.appendChild(importRoot(doc, genuine));

        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);
        Optional<LwsPrincipal> principal = validator.validate(serialize(doc));
        assertTrue(principal.isPresent());
        assertEquals(NAME_ID, principal.get().webId());
    }

    /** Every wrapping case must also prove the honest credential still authenticates. */
    private static void assertRejected(KeyPair idp, String wrapped) throws Exception {
        SamlValidator validator = new SamlValidator(List.of(idp.getPublic()), Set.of(ISSUER), null);
        Optional<LwsPrincipal> principal = validator.validate(wrapped);
        assertTrue(principal.isEmpty(),
                () -> "wrapped document authenticated as " + principal.map(LwsPrincipal::webId).orElse(null));
        assertTrue(validator.validate(signedAssertion(idpPrivate(idp), ISSUER, NAME_ID)).isPresent(),
                "the honest credential must still be accepted");
    }

    private static PrivateKey idpPrivate(KeyPair idp) {
        return idp.getPrivate();
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static String signedAssertion(PrivateKey signingKey, String issuer, String nameId) throws Exception {
        Document doc = newDocument();
        Element assertion = assertionElement(doc, "_a1", issuer, nameId);
        doc.appendChild(assertion);
        signEnveloped(assertion, signingKey, "#_a1");
        return serialize(doc);
    }

    private static Document newDocument() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().newDocument();
    }

    private static Element assertionElement(Document doc, String id, String issuer, String nameId) {
        Element assertion = doc.createElementNS(SAML_NS, "saml:Assertion");
        // Declare the namespace explicitly so the identity Transformer serializes it faithfully
        // (otherwise the implicit prefix declaration is dropped and canonicalization drifts).
        assertion.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:saml", SAML_NS);
        assertion.setAttribute("ID", id);
        assertion.setAttribute("Version", "2.0");
        assertion.setAttribute("IssueInstant", Instant.now().toString());

        Element issuerEl = doc.createElementNS(SAML_NS, "saml:Issuer");
        issuerEl.setTextContent(issuer);
        assertion.appendChild(issuerEl);

        Element subject = doc.createElementNS(SAML_NS, "saml:Subject");
        assertion.appendChild(subject);
        Element nameIdEl = doc.createElementNS(SAML_NS, "saml:NameID");
        nameIdEl.setTextContent(nameId);
        subject.appendChild(nameIdEl);
        Element sc = doc.createElementNS(SAML_NS, "saml:SubjectConfirmation");
        sc.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");
        subject.appendChild(sc);
        Element scd = doc.createElementNS(SAML_NS, "saml:SubjectConfirmationData");
        scd.setAttribute("Recipient", "https://client.example");
        sc.appendChild(scd);
        return assertion;
    }

    private static Element responseElement(Document doc, String id) {
        Element response = doc.createElementNS(SAMLP_NS, "samlp:Response");
        response.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:samlp", SAMLP_NS);
        response.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:saml", SAML_NS);
        response.setAttribute("ID", id);
        response.setAttribute("Version", "2.0");
        response.setAttribute("IssueInstant", Instant.now().toString());
        return response;
    }

    /** Sign {@code target} in place, referencing {@code refUri} ({@code ""} means the whole document). */
    private static void signEnveloped(Element target, PrivateKey signingKey, String refUri) throws Exception {
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        signEnveloped(target, signingKey, refUri, List.of(
                fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)));
    }

    private static void signEnveloped(Element target, PrivateKey signingKey, String refUri,
            List<Transform> transforms) throws Exception {
        if (target.hasAttribute("ID")) {
            target.setIdAttribute("ID", true);
        }
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref = fac.newReference(refUri, fac.newDigestMethod(DigestMethod.SHA256, null),
                transforms, null, null);
        SignedInfo signedInfo = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                Collections.singletonList(ref));
        fac.newXMLSignature(signedInfo, null).sign(new DOMSignContext(signingKey, target));
    }

    /** A signed assertion whose Conditions carry one {@code AudienceRestriction} per inner list. */
    private static String audienceRestrictedAssertion(PrivateKey signingKey,
            List<List<String>> restrictions) throws Exception {
        Document doc = newDocument();
        Element assertion = assertionElement(doc, "_a1", ISSUER, NAME_ID);
        doc.appendChild(assertion);
        Element conditions = doc.createElementNS(SAML_NS, "saml:Conditions");
        assertion.appendChild(conditions);
        for (List<String> audiences : restrictions) {
            Element restriction = doc.createElementNS(SAML_NS, "saml:AudienceRestriction");
            conditions.appendChild(restriction);
            for (String audience : audiences) {
                Element el = doc.createElementNS(SAML_NS, "saml:Audience");
                el.setTextContent(audience);
                restriction.appendChild(el);
            }
        }
        signEnveloped(assertion, signingKey, "#_a1");
        return serialize(doc);
    }

    /** A signed assertion whose {@code Conditions} carry the given window; a null bound is omitted. */
    private static String timeConditionedAssertion(PrivateKey signingKey,
            Instant notBefore, Instant notOnOrAfter) throws Exception {
        return timeConditionedAssertionRaw(signingKey,
                notBefore == null ? null : notBefore.toString(),
                notOnOrAfter == null ? null : notOnOrAfter.toString());
    }

    /**
     * The same, with the attribute values written verbatim — the malformed cases need a value
     * {@link Instant} cannot express. The {@code Conditions} element is appended before signing, so
     * the window the validator reads is the window the IdP signed.
     */
    private static String timeConditionedAssertionRaw(PrivateKey signingKey,
            String notBefore, String notOnOrAfter) throws Exception {
        Document doc = newDocument();
        Element assertion = assertionElement(doc, "_a1", ISSUER, NAME_ID);
        doc.appendChild(assertion);
        Element conditions = doc.createElementNS(SAML_NS, "saml:Conditions");
        if (notBefore != null) {
            conditions.setAttribute("NotBefore", notBefore);
        }
        if (notOnOrAfter != null) {
            conditions.setAttribute("NotOnOrAfter", notOnOrAfter);
        }
        assertion.appendChild(conditions);
        signEnveloped(assertion, signingKey, "#_a1");
        return serialize(doc);
    }

    /**
     * Re-parent an already-serialized document's root into {@code doc}. Going through the wire form
     * rather than moving DOM nodes directly is the point: it proves the relocated assertion is the
     * genuine credential, byte for byte, and exclusive canonicalization re-emits the namespace
     * declarations at the reference node-set's apex, so the signature still verifies afterwards.
     */
    private static Element importRoot(Document doc, String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document parsed = dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        return (Element) doc.importNode(parsed.getDocumentElement(), true);
    }

    private static Element signatureOf(Element parent) {
        return (Element) parent.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
    }

    private static String serialize(Node node) throws Exception {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        StringWriter out = new StringWriter();
        transformer.transform(new DOMSource(node), new StreamResult(out));
        return out.toString();
    }
}
