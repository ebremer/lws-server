package com.ebremer.lws.server.core;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.rdfconnection.RDFConnection;
import org.apache.jena.vocabulary.DCTerms;
import org.apache.jena.vocabulary.RDF;
import com.ebremer.lws.server.vocab.LWS;

/**
 * Persists and queries the administrative metadata that describes every LWS resource (type,
 * containment, timestamps, etag, ACL, binary pointers). The metadata lives in a dedicated
 * named graph so it never mixes with resource content graphs.
 *
 * <p>All methods operate on a caller-provided {@link RDFConnection} so they participate in the
 * caller's transaction. Variable IRIs are bound via {@link ParameterizedSparqlString} to avoid
 * injection.
 *
 * @author Erich Bremer
 */
public final class ResourceRegistry {

    /** The named graph holding administrative metadata. */
    public static final String ADMIN_GRAPH = "urn:x-lws:admin";

    /** A contained child: its IRI and whether it is itself a container. */
    public record ChildRef(String iri, boolean container) {
    }

    /** A contained child with the metadata needed for a container listing. */
    public record ChildDesc(String iri, boolean container, String mediaType, long size, Instant modified) {
    }

    private final String adminGraph;

    public ResourceRegistry() {
        this(ADMIN_GRAPH);
    }

    public ResourceRegistry(String adminGraph) {
        this.adminGraph = adminGraph;
    }

    public boolean exists(RDFConnection conn, String iri) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("ASK { GRAPH ?g { ?s ?p ?o } }");
        q.setIri("g", adminGraph);
        q.setIri("s", iri);
        return conn.queryAsk(q.asQuery());
    }

    public Optional<LwsResource> find(RDFConnection conn, String iri) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("CONSTRUCT { ?s ?p ?o } WHERE { GRAPH ?g { ?s ?p ?o } }");
        q.setIri("g", adminGraph);
        q.setIri("s", iri);
        Model m = conn.queryConstruct(q.asQuery());
        if (m.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(fromModel(iri, m));
    }

    public void put(RDFConnection conn, LwsResource r) {
        deleteSubject(conn, r.iri());
        conn.load(adminGraph, toModel(r));
    }

    public void delete(RDFConnection conn, String iri) {
        deleteSubject(conn, iri);
    }

    private void deleteSubject(RDFConnection conn, String iri) {
        ParameterizedSparqlString u = new ParameterizedSparqlString();
        u.setCommandText("DELETE WHERE { GRAPH ?g { ?s ?p ?o } }");
        u.setIri("g", adminGraph);
        u.setIri("s", iri);
        conn.update(u.asUpdate());
    }

    /** The direct children of a container, ordered by IRI. */
    public List<ChildRef> children(RDFConnection conn, String containerIri) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("""
                SELECT ?c ?t WHERE {
                  GRAPH ?g { ?c <%s> ?container . ?c a ?t }
                } ORDER BY ?c""".formatted(LWS.parent.getURI()));
        q.setIri("g", adminGraph);
        q.setIri("container", containerIri);
        List<ChildRef> out = new ArrayList<>();
        conn.querySelect(q.asQuery(), row -> {
            String iri = row.getResource("c").getURI();
            boolean container = row.getResource("t").getURI().equals(LWS.Container.getURI());
            out.add(new ChildRef(iri, container));
        });
        return out;
    }

    /** The direct children of a container with listing metadata (type, media type, size, modified). */
    public List<ChildDesc> childDescriptions(RDFConnection conn, String containerIri) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("""
                SELECT ?c ?t ?fmt ?size ?mod WHERE {
                  GRAPH ?g {
                    ?c <%s> ?container ; a ?t .
                    OPTIONAL { ?c <%s> ?fmt }
                    OPTIONAL { ?c <%s> ?size }
                    OPTIONAL { ?c <%s> ?mod }
                  }
                } ORDER BY ?c""".formatted(
                LWS.parent.getURI(), DCTerms.format.getURI(), LWS.byteSize.getURI(), DCTerms.modified.getURI()));
        q.setIri("g", adminGraph);
        q.setIri("container", containerIri);
        List<ChildDesc> out = new ArrayList<>();
        conn.querySelect(q.asQuery(), row -> {
            boolean container = row.getResource("t").getURI().equals(LWS.Container.getURI());
            String mediaType = row.contains("fmt") ? row.getLiteral("fmt").getString() : null;
            long size = row.contains("size") ? row.getLiteral("size").getLong() : -1L;
            Instant modified = row.contains("mod") ? Instant.parse(row.getLiteral("mod").getString()) : null;
            out.add(new ChildDesc(row.getResource("c").getURI(), container, mediaType, size, modified));
        });
        return out;
    }

    /** The sum of {@code lws:byteSize} across all resources (total stored binary content). */
    public long totalBytes(RDFConnection conn) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("SELECT (SUM(?n) AS ?total) WHERE { GRAPH ?g { ?s <%s> ?n } }"
                .formatted(LWS.byteSize.getURI()));
        q.setIri("g", adminGraph);
        long[] total = {0L};
        conn.querySelect(q.asQuery(), row -> {
            if (row.contains("total") && row.getLiteral("total") != null) {
                total[0] = row.getLiteral("total").getLong();
            }
        });
        return total[0];
    }

    public boolean hasChildren(RDFConnection conn, String containerIri) {
        ParameterizedSparqlString q = new ParameterizedSparqlString();
        q.setCommandText("ASK { GRAPH ?g { ?c <%s> ?container } }".formatted(LWS.parent.getURI()));
        q.setIri("g", adminGraph);
        q.setIri("container", containerIri);
        return conn.queryAsk(q.asQuery());
    }

    // ----- mapping -----

    private Model toModel(LwsResource r) {
        Model m = ModelFactory.createDefaultModel();
        Resource s = m.createResource(r.iri());
        s.addProperty(RDF.type, r.isContainer() ? LWS.Container : LWS.DataResource);
        if (r.parentIri() != null) {
            s.addProperty(LWS.parent, m.createResource(r.parentIri()));
        }
        if (r.created() != null) {
            s.addProperty(DCTerms.created, m.createTypedLiteral(r.created().toString(), XSDDatatype.XSDdateTime));
        }
        if (r.modified() != null) {
            s.addProperty(DCTerms.modified, m.createTypedLiteral(r.modified().toString(), XSDDatatype.XSDdateTime));
        }
        if (r.etag() != null) {
            s.addProperty(LWS.etag, r.etag());
        }
        if (r.contentType() != null) {
            s.addProperty(DCTerms.format, r.contentType());
        }
        if (r.type() == ResourceType.NON_RDF_SOURCE) {
            s.addLiteral(LWS.byteSize, r.size());
            if (r.binaryKey() != null) {
                s.addProperty(LWS.binaryKey, r.binaryKey());
            }
            if (r.digest() != null) {
                s.addProperty(LWS.contentSha256, r.digest());
            }
        }
        if (r.owner() != null) {
            s.addProperty(LWS.owner, m.createResource(r.owner()));
        }
        s.addLiteral(LWS.publicRead, r.publicRead());
        return m;
    }

    private LwsResource fromModel(String iri, Model m) {
        Resource s = m.getResource(iri);
        ResourceType type;
        if (s.hasProperty(RDF.type, LWS.Container)) {
            type = ResourceType.CONTAINER;
        } else if (s.hasProperty(LWS.binaryKey)) {
            type = ResourceType.NON_RDF_SOURCE;
        } else {
            type = ResourceType.RDF_SOURCE;
        }
        String parent = s.hasProperty(LWS.parent) ? s.getProperty(LWS.parent).getResource().getURI() : null;
        Instant created = instant(s, DCTerms.created);
        Instant modified = instant(s, DCTerms.modified);
        String etag = string(s, LWS.etag);
        String contentType = string(s, DCTerms.format);
        long size = s.hasProperty(LWS.byteSize) ? s.getProperty(LWS.byteSize).getLong() : -1L;
        String binaryKey = string(s, LWS.binaryKey);
        String owner = s.hasProperty(LWS.owner) ? s.getProperty(LWS.owner).getResource().getURI() : null;
        boolean publicRead = s.hasProperty(LWS.publicRead) && s.getProperty(LWS.publicRead).getBoolean();
        String digest = string(s, LWS.contentSha256);
        return new LwsResource(iri, type, parent, created, modified, etag, contentType, size, binaryKey,
                owner, publicRead, digest);
    }

    private static Instant instant(Resource s, org.apache.jena.rdf.model.Property p) {
        Statement st = s.getProperty(p);
        return st == null ? null : Instant.parse(st.getString());
    }

    private static String string(Resource s, org.apache.jena.rdf.model.Property p) {
        Statement st = s.getProperty(p);
        return st == null ? null : st.getString();
    }
}
