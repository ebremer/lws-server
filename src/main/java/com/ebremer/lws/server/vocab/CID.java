package com.ebremer.lws.server.vocab;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

/**
 * The terms of W3C Controlled Identifiers 1.0 that this server writes and reads, with the IRIs the
 * CID v1 JSON-LD context ({@value #CONTEXT}) maps them to.
 *
 * <p>An LWS storage description is a controlled identifier document (lws10-core, Storage
 * Description Resource), so its {@code service}, {@code serviceEndpoint}, {@code verificationMethod}
 * and {@code authentication} are CID terms rather than LWS ones. The subject documents the
 * authentication suites dereference are controlled identifier documents too.
 *
 * @author Erich Bremer
 */
public final class CID {

    private CID() {
    }

    /** The CID v1 JSON-LD context, which must come first in a storage description's {@code @context}. */
    public static final String CONTEXT = "https://www.w3.org/ns/cid/v1";

    /** The security vocabulary most CID terms live in. */
    public static final String SEC = "https://w3id.org/security#";

    /** The DID vocabulary, which is where the CID context puts {@code service}. */
    public static final String DID = "https://www.w3.org/ns/did#";

    private static final Model M = ModelFactory.createDefaultModel();

    public static final Property service = M.createProperty(DID + "service");
    public static final Property serviceEndpoint = M.createProperty(DID + "serviceEndpoint");
    public static final Property verificationMethod = M.createProperty(SEC + "verificationMethod");
    /** {@code authentication} in JSON; the context maps it to {@code sec:authenticationMethod}. */
    public static final Property authentication = M.createProperty(SEC + "authenticationMethod");
    public static final Property assertionMethod = M.createProperty(SEC + "assertionMethod");
    public static final Property controller = M.createProperty(SEC + "controller");
    public static final Property publicKeyJwk = M.createProperty(SEC + "publicKeyJwk");
    public static final Property publicKeyMultibase = M.createProperty(SEC + "publicKeyMultibase");
    public static final Property revoked = M.createProperty(SEC + "revoked");
    /** {@code expires} in JSON; the context maps it to {@code sec:expiration}. */
    public static final Property expires = M.createProperty(SEC + "expiration");

    public static final Resource JsonWebKey = M.createResource(SEC + "JsonWebKey");
    public static final Resource Multikey = M.createResource(SEC + "Multikey");

    /** The {@code rdf:JSON} datatype a {@code publicKeyJwk} value carries ({@code "@type": "@json"}). */
    public static final String RDF_JSON = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";
}
