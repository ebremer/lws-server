package com.ebremer.lws.server.vocab;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

/**
 * The Web Access Control (WAC) vocabulary used for multi-user authorization.
 *
 * <p>Namespace: {@code http://www.w3.org/ns/auth/acl#}. WAC governs access through
 * {@code acl:Authorization} statements that bind agents (or agent classes) and access modes to
 * resources, with container-based inheritance via {@code acl:default}.
 *
 * @author Erich Bremer
 */
public final class ACL {

    private ACL() {
    }

    public static final String NS = "http://www.w3.org/ns/auth/acl#";
    public static final String PREFIX = "acl";

    public static String getURI() {
        return NS;
    }

    private static final Model M = ModelFactory.createDefaultModel();

    private static Resource r(String local) {
        return M.createResource(NS + local);
    }

    private static Property p(String local) {
        return M.createProperty(NS + local);
    }

    // Classes
    /** An authorization rule. */
    public static final Resource Authorization = r("Authorization");
    /** The class of all authenticated agents. */
    public static final Resource AuthenticatedAgent = r("AuthenticatedAgent");

    // Access modes
    public static final Resource Read = r("Read");
    public static final Resource Write = r("Write");
    public static final Resource Append = r("Append");
    public static final Resource Control = r("Control");

    // Properties
    /** The resource(s) this authorization applies to directly. */
    public static final Property accessTo = p("accessTo");
    /** The container whose contained resources inherit this authorization ({@code acl:default}). */
    public static final Property defaultAccess = p("default");
    /** A specific agent (WebID) this authorization applies to. */
    public static final Property agent = p("agent");
    /** A class of agents (e.g. {@code foaf:Agent}, {@code acl:AuthenticatedAgent}). */
    public static final Property agentClass = p("agentClass");
    /** A group of agents. */
    public static final Property agentGroup = p("agentGroup");
    /** A web origin (browser application) this authorization is restricted to. */
    public static final Property origin = p("origin");
    /** An access mode granted by this authorization. */
    public static final Property mode = p("mode");
}
