package com.ebremer.lws.server.vocab;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;

/**
 * The single FOAF term WAC needs: {@code foaf:Agent}, the agent class meaning "everyone"
 * (the public) in {@code acl:agentClass} authorizations.
 *
 * @author Erich Bremer
 */
public final class FOAF {

    private FOAF() {
    }

    public static final String NS = "http://xmlns.com/foaf/0.1/";
    public static final String PREFIX = "foaf";

    private static final Model M = ModelFactory.createDefaultModel();

    /** The class of all agents — used as the "public" agent class in WAC. */
    public static final Resource Agent = M.createResource(NS + "Agent");
}
