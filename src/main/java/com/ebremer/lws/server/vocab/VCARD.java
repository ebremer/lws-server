package com.ebremer.lws.server.vocab;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

/**
 * The vCard terms WAC uses for groups: an {@code acl:agentGroup} points at a {@code vcard:Group}
 * whose members are listed with {@code vcard:hasMember}.
 *
 * <p>Namespace: {@code http://www.w3.org/2006/vcard/ns#}.
 *
 * @author Erich Bremer
 */
public final class VCARD {

    private VCARD() {
    }

    public static final String NS = "http://www.w3.org/2006/vcard/ns#";
    public static final String PREFIX = "vcard";

    private static final Model M = ModelFactory.createDefaultModel();

    public static final Resource Group = M.createResource(NS + "Group");
    public static final Property hasMember = M.createProperty(NS + "hasMember");
}
