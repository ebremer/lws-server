package com.ebremer.lws.server.auth;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Validates an LWS SAML 2.0 authentication credential, per
 * <a href="https://w3c.github.io/lws-protocol/lws10-authn-saml/">LWS Authentication: SAML 2.0</a>.
 * The credential is a signed SAML assertion. Trust is established out of band: the verifier is
 * configured with the trusted identity provider's public key(s) (and, optionally, trusted issuer
 * entity IDs). The assertion's XML signature is validated per SAML Core §5 and the
 * {@code Issuer}/{@code NameID}/{@code Recipient} are mapped to the LWS subject/issuer/client.
 *
 * @author Erich Bremer
 */
public final class SamlValidator implements CredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(SamlValidator.class);

    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

    private final List<PublicKey> trustedKeys;
    private final Set<String> trustedIssuers; // empty => any issuer with a trusted signing key
    private final String expectedAudience;    // null => audience not checked

    public SamlValidator(List<PublicKey> trustedKeys, Set<String> trustedIssuers, String expectedAudience) {
        this.trustedKeys = List.copyOf(trustedKeys);
        this.trustedIssuers = Set.copyOf(trustedIssuers);
        this.expectedAudience = expectedAudience;
    }

    /** Load IdP public keys from PEM/DER X.509 certificate files. */
    public static List<PublicKey> loadTrustedKeys(List<String> certificatePaths) {
        List<PublicKey> keys = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (String path : certificatePaths) {
                try (InputStream in = Files.newInputStream(Path.of(path))) {
                    for (Certificate cert : cf.generateCertificates(in)) {
                        keys.add(cert.getPublicKey());
                    }
                } catch (Exception e) {
                    LoggerFactory.getLogger(SamlValidator.class)
                            .warn("Could not load SAML IdP certificate {}: {}", path, e.toString());
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("X.509 certificate factory unavailable", e);
        }
        return keys;
    }

    @Override
    public Optional<LwsPrincipal> validate(String credential) {
        try {
            byte[] xml = toXmlBytes(credential);
            if (xml == null) {
                return Optional.empty();
            }
            Document doc = parseSecure(xml);
            Element assertion = firstElement(doc, SAML_NS, "Assertion");
            if (assertion == null) {
                return Optional.empty();
            }
            registerIdAttributes(doc);

            if (!signatureIsTrusted(doc)) {
                log.debug("SAML credential: no valid signature from a trusted key");
                return Optional.empty();
            }
            if (!withinValidity(assertion)) {
                log.debug("SAML credential: outside Conditions validity window");
                return Optional.empty();
            }
            String issuer = text(firstChild(assertion, SAML_NS, "Issuer"));
            if (!trustedIssuers.isEmpty() && (issuer == null || !trustedIssuers.contains(issuer))) {
                log.debug("SAML credential: issuer {} is not trusted", issuer);
                return Optional.empty();
            }
            Element subject = firstChild(assertion, SAML_NS, "Subject");
            String nameId = subject == null ? null : text(firstChild(subject, SAML_NS, "NameID"));
            if (nameId == null) {
                log.debug("SAML credential: missing Subject NameID");
                return Optional.empty();
            }
            if (!audienceOk(assertion)) {
                log.debug("SAML credential: audience restriction does not include {}", expectedAudience);
                return Optional.empty();
            }
            return Optional.of(new LwsPrincipal(nameId, issuer, recipient(subject)));
        } catch (Exception e) {
            log.debug("SAML validation failed: {}", e.toString());
            return Optional.empty();
        }
    }

    private boolean signatureIsTrusted(Document doc) throws Exception {
        NodeList signatures = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        for (int i = 0; i < signatures.getLength(); i++) {
            Node sigNode = signatures.item(i);
            for (PublicKey key : trustedKeys) {
                try {
                    DOMValidateContext context = new DOMValidateContext(key, sigNode);
                    XMLSignature signature = factory.unmarshalXMLSignature(context);
                    if (signature.validate(context)) {
                        return true;
                    }
                } catch (Exception ignore) {
                    // try the next key / signature
                }
            }
        }
        return false;
    }

    private boolean audienceOk(Element assertion) {
        if (expectedAudience == null) {
            return true;
        }
        Element conditions = firstChild(assertion, SAML_NS, "Conditions");
        if (conditions == null) {
            return true; // no audience restriction present
        }
        NodeList audiences = conditions.getElementsByTagNameNS(SAML_NS, "Audience");
        if (audiences.getLength() == 0) {
            return true;
        }
        for (int i = 0; i < audiences.getLength(); i++) {
            if (expectedAudience.equals(text(audiences.item(i)))) {
                return true;
            }
        }
        return false;
    }

    private static boolean withinValidity(Element assertion) {
        Element conditions = firstChild(assertion, SAML_NS, "Conditions");
        if (conditions == null) {
            return true;
        }
        long now = System.currentTimeMillis();
        long skew = JwsSupport.CLOCK_SKEW_MS;
        String notBefore = conditions.getAttribute("NotBefore");
        String notOnOrAfter = conditions.getAttribute("NotOnOrAfter");
        if (!notBefore.isEmpty() && Instant.parse(notBefore).toEpochMilli() - skew > now) {
            return false;
        }
        if (!notOnOrAfter.isEmpty() && Instant.parse(notOnOrAfter).toEpochMilli() + skew <= now) {
            return false;
        }
        return true;
    }

    private static String recipient(Element subject) {
        if (subject == null) {
            return null;
        }
        Element confirmation = firstChild(subject, SAML_NS, "SubjectConfirmation");
        if (confirmation == null) {
            return null;
        }
        Element data = firstChild(confirmation, SAML_NS, "SubjectConfirmationData");
        if (data == null || !data.hasAttribute("Recipient")) {
            return null;
        }
        return data.getAttribute("Recipient");
    }

    // ----- XML helpers -----

    private static byte[] toXmlBytes(String credential) {
        String t = credential.trim();
        if (t.startsWith("<")) {
            return t.getBytes(StandardCharsets.UTF_8);
        }
        try {
            return Base64.getMimeDecoder().decode(t);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static Document parseSecure(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml));
    }

    /** Mark the {@code ID} attributes on Assertion/Response so signature references resolve. */
    private static void registerIdAttributes(Document doc) {
        markId(doc.getElementsByTagNameNS(SAML_NS, "Assertion"));
        markId(doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "Response"));
    }

    private static void markId(NodeList nodes) {
        for (int i = 0; i < nodes.getLength(); i++) {
            Element e = (Element) nodes.item(i);
            if (e.hasAttribute("ID")) {
                e.setIdAttribute("ID", true);
            }
        }
    }

    private static Element firstElement(Document doc, String ns, String local) {
        NodeList nl = doc.getElementsByTagNameNS(ns, local);
        return nl.getLength() == 0 ? null : (Element) nl.item(0);
    }

    private static Element firstChild(Element parent, String ns, String local) {
        NodeList nl = parent.getElementsByTagNameNS(ns, local);
        return nl.getLength() == 0 ? null : (Element) nl.item(0);
    }

    private static String text(Node node) {
        return node == null ? null : node.getTextContent().trim();
    }
}
