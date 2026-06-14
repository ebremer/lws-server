package com.ebremer.lws.server.vocab;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;

/**
 * The handful of W3C Linked Data Platform terms that LWS reuses for interoperability,
 * primarily the {@code Link: rel="type"} interaction-model markers used during resource
 * creation (LWS derives its container model from LDP / the Solid Protocol).
 *
 * <p>Namespace: {@code http://www.w3.org/ns/ldp#}.
 *
 * @author Erich Bremer
 */
public final class LDP {

    private LDP() {
    }

    public static final String NS = "http://www.w3.org/ns/ldp#";
    public static final String PREFIX = "ldp";

    public static String getURI() {
        return NS;
    }

    private static final Model M = ModelFactory.createDefaultModel();

    public static final Resource Resource = M.createResource(NS + "Resource");
    public static final Resource RDFSource = M.createResource(NS + "RDFSource");
    public static final Resource NonRDFSource = M.createResource(NS + "NonRDFSource");
    public static final Resource Container = M.createResource(NS + "Container");
    public static final Resource BasicContainer = M.createResource(NS + "BasicContainer");

    /** The full IRI strings, handy for Link-header comparisons. */
    public static final String RESOURCE = NS + "Resource";
    public static final String RDF_SOURCE = NS + "RDFSource";
    public static final String NON_RDF_SOURCE = NS + "NonRDFSource";
    public static final String CONTAINER = NS + "Container";
    public static final String BASIC_CONTAINER = NS + "BasicContainer";
}
