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
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
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
 * <p><b>Signature wrapping.</b> A valid signature somewhere in a document proves nothing about the
 * element whose claims are read. Every check here exists to collapse the two into one element: the
 * document must carry exactly one {@code saml:Assertion} and exactly one {@code ds:Signature}; that
 * signature must be a <em>direct child</em> of that assertion; it must carry exactly one
 * {@code Reference} whose URI is literally {@code #<the assertion's ID>}; that ID must be unique in
 * the document and must resolve back to the same node; and the transform chain must be a plain
 * enveloped signature. Claims are then read by direct-child traversal, never by descendant search,
 * so a nested assertion inside {@code saml:Advice} can never supply one.
 *
 * <p>The profile this buys is deliberately narrow, and the restrictions are worth stating plainly.
 * A {@code samlp:Response} that signs the response rather than the assertion is refused; so is one
 * that signs <em>both</em>, which some identity providers emit; so is any legitimately
 * {@code Advice}-nested assertion. A single signed assertion enclosed in an <em>unsigned</em>
 * {@code samlp:Response} — the commonest shape in practice — is accepted. There is no setting to
 * relax any of this, because relaxing it is the vulnerability.
 *
 * @author Erich Bremer
 */
public final class SamlValidator implements CredentialValidator {

    private static final Logger log = LoggerFactory.getLogger(SamlValidator.class);

    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

    /**
     * Switches on the JDK's own XML signature hardening, which forbids XSLT transforms, RSA keys
     * below 1024 bits, and more than 30 references per manifest. It is already the default on
     * current JDKs, but it is set explicitly to pin the behaviour. Treat it strictly as defence in
     * depth: a JVM started with {@code -Dorg.jcp.xml.dsig.secureValidation=false} disables it
     * globally and this per-context property cannot override that. Nothing below relies on it —
     * every rule the binding depends on is enforced here directly, and secure validation does not
     * cover them anyway (it rejects XSLT but permits both XPath dialects).
     */
    private static final String SECURE_VALIDATION = "org.jcp.xml.dsig.secureValidation";

    /**
     * Canonicalization algorithms permitted as the optional companion to the enveloped-signature
     * transform. Anything outside this set — XPath, XPath Filter 2, XSLT, base64 — can select a
     * node-set unrelated to the element the reference names, decoupling what was digested from what
     * the URI claims, which is exactly the property the binding check exists to deny.
     */
    private static final Set<String> C14N_ALGORITHMS = Set.of(
            CanonicalizationMethod.EXCLUSIVE,
            CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
            CanonicalizationMethod.INCLUSIVE,
            CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
            // Spelled out because this JDK's CanonicalizationMethod has no C14N11 constant.
            "http://www.w3.org/2006/12/xml-c14n11",
            "http://www.w3.org/2006/12/xml-c14n11#WithComments");

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
            NodeList assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
            if (assertions.getLength() != 1) {
                log.debug("SAML credential: expected exactly one saml:Assertion, found {}",
                        assertions.getLength());
                return Optional.empty();
            }
            Element assertion = (Element) assertions.item(0);

            if (!signatureBindsAssertion(doc, assertion)) {
                log.debug("SAML credential: no trusted signature is bound to the assertion");
                return Optional.empty();
            }
            if (!withinValidity(assertion)) {
                log.debug("SAML credential: outside Conditions validity window");
                return Optional.empty();
            }
            String issuer = text(directChild(assertion, SAML_NS, "Issuer"));
            if (!trustedIssuers.isEmpty() && (issuer == null || !trustedIssuers.contains(issuer))) {
                log.debug("SAML credential: issuer {} is not trusted", issuer);
                return Optional.empty();
            }
            Element subject = directChild(assertion, SAML_NS, "Subject");
            String nameId = subject == null ? null : text(directChild(subject, SAML_NS, "NameID"));
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

    /**
     * True when the document carries exactly one signature, that signature is the assertion's own
     * enveloped signature covering the whole assertion and nothing else, and it verifies under a
     * trusted IdP key. Every structural rule is decided before the signature is verified, and a
     * structural failure aborts outright rather than falling through to the next key — none of them
     * depend on which key is tried.
     */
    private boolean signatureBindsAssertion(Document doc, Element assertion) {
        if (doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").getLength() != 1) {
            log.debug("SAML credential: expected exactly one ds:Signature in the document");
            return false;
        }
        // A direct-child scan, never getElementsByTagNameNS. SAML Core puts the signature after
        // saml:Issuer and the JDK's own DOMSignContext(key, element) appends it last, so any child
        // position is accepted — but it must never descend: a signature inside saml:Advice belongs
        // to a nested assertion, not to this one, and treating it as this one's is the whole bug.
        Element signatureElement = directChild(assertion, XMLSignature.XMLNS, "Signature");
        if (signatureElement == null) {
            log.debug("SAML credential: the ds:Signature is not a direct child of the assertion");
            return false;
        }
        String id = assertion.getAttribute("ID");
        if (id.isEmpty()) {
            log.debug("SAML credential: the assertion has no ID for a signature to name");
            return false;
        }
        if (!idIsUniqueTo(doc, id, assertion)) {
            log.debug("SAML credential: ID {} appears on more than one element", id);
            return false;
        }
        // Mark the ID on this assertion and on nothing else. The dereferencer resolves a
        // same-document reference through Document.getElementById first and the validation
        // context's own map only as a fallback, so marking exactly one element leaves the reference
        // with exactly one element it can possibly resolve to. Marking every assertion — which this
        // class used to do — is what let a wrapped-away original's "#_a1" still resolve and digest.
        assertion.setIdAttribute("ID", true);

        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        for (PublicKey key : trustedKeys) {
            // A fresh unmarshal per key is required, not merely tidy: XMLSignature.validate caches
            // its verdict, so reusing one signature object would hand every later key the first
            // key's answer — silently breaking any deployment with more than one IdP certificate.
            DOMValidateContext context = new DOMValidateContext(key, signatureElement);
            context.setProperty(SECURE_VALIDATION, Boolean.TRUE);
            XMLSignature signature;
            try {
                signature = factory.unmarshalXMLSignature(context);
            } catch (Exception e) {
                log.debug("SAML credential: signature could not be read: {}", e.toString());
                return false;
            }
            List<Reference> references = signature.getSignedInfo().getReferences();
            if (references.size() != 1) {
                log.debug("SAML credential: SignedInfo carries {} references, expected one",
                        references.size());
                return false;
            }
            Reference reference = references.get(0);
            // Literal string equality, deliberately, with the constant on the left: getURI returns
            // null for an absent URI attribute and "" for a whole-document reference, and the
            // dereferencer also honours same-document XPointers such as "#xpointer(id('_a1'))" —
            // which resolve to the right element yet sail past any check that merely strips a '#'.
            if (!("#" + id).equals(reference.getURI())) {
                log.debug("SAML credential: reference URI {} does not name the assertion",
                        reference.getURI());
                return false;
            }
            if (!isEnvelopedOnly(reference)) {
                log.debug("SAML credential: the reference transform chain is not a plain enveloped signature");
                return false;
            }
            if (!assertion.isSameNode(doc.getElementById(id))) {
                log.debug("SAML credential: ID {} does not resolve back to the assertion", id);
                return false;
            }
            try {
                if (signature.validate(context)) {
                    return true;
                }
            } catch (Exception e) {
                log.debug("SAML credential: signature validation error: {}", e.toString());
            }
        }
        return false;
    }

    /**
     * True when the transform chain is the enveloped-signature transform plus at most one
     * canonicalization, in either order. Enveloped is required rather than merely permitted: the
     * signature sits inside the element the reference names, so a chain that did not remove it
     * could not have digested this assertion.
     */
    private static boolean isEnvelopedOnly(Reference reference) {
        boolean enveloped = false;
        int canonicalizations = 0;
        for (Transform transform : reference.getTransforms()) {
            String algorithm = transform.getAlgorithm();
            if (Transform.ENVELOPED.equals(algorithm)) {
                if (enveloped) {
                    return false;
                }
                enveloped = true;
            } else if (C14N_ALGORITHMS.contains(algorithm)) {
                if (++canonicalizations > 1) {
                    return false;
                }
            } else {
                return false;
            }
        }
        return enveloped;
    }

    /**
     * True when {@code element} is the only element in the document carrying this {@code ID}.
     * Without it a wrapper could reuse the genuine assertion's ID, and which of the two a reference
     * resolved to would come down to DOM implementation detail.
     */
    private static boolean idIsUniqueTo(Document doc, String id, Element element) {
        NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Element candidate = (Element) all.item(i);
            if (id.equals(candidate.getAttribute("ID")) && !candidate.isSameNode(element)) {
                return false;
            }
        }
        return true;
    }

    /**
     * True when the assertion's audience restrictions admit this storage.
     *
     * <p>SAML Core §2.5.1.4 makes the two levels mean opposite things: the {@code Audience} values
     * <em>within</em> one {@code AudienceRestriction} are a disjunction, but several
     * {@code AudienceRestriction} elements are a conjunction — each is evaluated independently and
     * all must hold. Treating the whole set as one flat disjunction, as this method once did,
     * accepts an assertion the IdP restricted to us <em>and</em> to somebody else, which is the
     * opposite of what the second restriction was added to say.
     *
     * <p>When an audience is configured the restriction is also required: an assertion with no
     * {@code Conditions}, or none naming an audience at all, is refused rather than waved through.
     * Leaving {@code lws.saml.audience} unset keeps the check off entirely, so this tightens only
     * the deployments that asked for it.
     */
    private boolean audienceOk(Element assertion) {
        if (expectedAudience == null) {
            return true;
        }
        Element conditions = directChild(assertion, SAML_NS, "Conditions");
        if (conditions == null) {
            return false;
        }
        boolean restricted = false;
        for (Node n = conditions.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() != Node.ELEMENT_NODE || !SAML_NS.equals(n.getNamespaceURI())
                    || !"AudienceRestriction".equals(n.getLocalName())) {
                continue;
            }
            restricted = true;
            if (!namesUs((Element) n)) {
                return false; // this restriction excludes us, and every restriction must hold
            }
        }
        return restricted;
    }

    /** True when one {@code AudienceRestriction} lists this storage among its audiences. */
    private boolean namesUs(Element restriction) {
        for (Node a = restriction.getFirstChild(); a != null; a = a.getNextSibling()) {
            if (a.getNodeType() == Node.ELEMENT_NODE && SAML_NS.equals(a.getNamespaceURI())
                    && "Audience".equals(a.getLocalName()) && expectedAudience.equals(text(a))) {
                return true;
            }
        }
        return false;
    }

    private static boolean withinValidity(Element assertion) {
        Element conditions = directChild(assertion, SAML_NS, "Conditions");
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
        Element confirmation = directChild(subject, SAML_NS, "SubjectConfirmation");
        if (confirmation == null) {
            return null;
        }
        Element data = directChild(confirmation, SAML_NS, "SubjectConfirmationData");
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

    /**
     * The first direct child element with this name. Unlike {@code getElementsByTagNameNS} this
     * never descends, so an assertion nested in {@code saml:Advice} can never supply a claim that
     * document order would otherwise hand it.
     */
    private static Element directChild(Element parent, String ns, String local) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && ns.equals(n.getNamespaceURI()) && local.equals(n.getLocalName())) {
                return (Element) n;
            }
        }
        return null;
    }

    /**
     * The element's text, concatenating every text node exactly as canonicalization does. Do not
     * narrow this to the first text node: {@code <NameID>owner@example.com<!--x-->.attacker.example}
     * would then read back as the owner's identifier while the signature covers the whole string —
     * the 2018 SAML comment-injection bug.
     */
    private static String text(Node node) {
        return node == null ? null : node.getTextContent().trim();
    }
}
