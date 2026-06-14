package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Tests the SAML 2.0 suite: a signed assertion is accepted only when signed by a trusted key,
 * from a trusted issuer, and untampered.
 *
 * @author Erich Bremer
 */
class SamlValidatorTest {

    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String ISSUER = "https://idp.example";
    private static final String NAME_ID = "https://alice.example/profile#me";

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

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static String signedAssertion(PrivateKey signingKey, String issuer, String nameId) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();

        Element assertion = doc.createElementNS(SAML_NS, "saml:Assertion");
        // Declare the namespace explicitly so the identity Transformer serializes it faithfully
        // (otherwise the implicit prefix declaration is dropped and canonicalization drifts).
        assertion.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:saml", SAML_NS);
        assertion.setAttribute("ID", "_a1");
        assertion.setAttribute("Version", "2.0");
        assertion.setAttribute("IssueInstant", Instant.now().toString());
        doc.appendChild(assertion);

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

        assertion.setIdAttribute("ID", true);

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref = fac.newReference("#_a1", fac.newDigestMethod(DigestMethod.SHA256, null),
                List.of(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)),
                null, null);
        SignedInfo signedInfo = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                Collections.singletonList(ref));
        DOMSignContext signContext = new DOMSignContext(signingKey, assertion);
        fac.newXMLSignature(signedInfo, null).sign(signContext);

        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        StringWriter out = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(out));
        return out.toString();
    }
}
