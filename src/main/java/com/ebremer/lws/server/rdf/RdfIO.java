package com.ebremer.lws.server.rdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.apache.jena.graph.Node;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.riot.RiotException;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.DatasetGraphFactory;

/**
 * Thin helpers for parsing and serializing RDF models to/from bytes.
 *
 * @author Erich Bremer
 */
public final class RdfIO {

    static {
        // Refuse remote JSON-LD @context dereferencing before any parse can happen. Titanium's
        // stock loader would fetch http/https/file URLs chosen by the document being parsed.
        // LwsComponents may widen this to an allow-list from lws.jsonld.allowed-context-hosts.
        JsonLdSecurity.installDefault();
    }

    private RdfIO() {
    }

    /**
     * Parse bytes into a new model, resolving relative IRIs against {@code baseIri}.
     *
     * <p>Parsed as a dataset and then reduced to its default graph, so that a document carrying
     * data a {@link Model} cannot hold is <em>refused</em> rather than truncated. Reading a
     * quad-bearing serialization straight into a Model has Jena drop every non-default-graph quad
     * with a one-time log line the client never sees: {@code PUT} answered {@code 201}, the
     * entity-tag was computed over what survived, and the client had no way to tell (finding M38).
     * TriG is the obvious case, but JSON-LD reaches it too — a node object carrying {@code @graph}
     * is a named graph, which is exactly how a merge-patch over RDF used to destroy a graph and
     * report success (finding H21).
     *
     * <p>Only the <em>presence of data</em> outside the default graph is refused, so every
     * triples-only serialization and every quad serialization that stays in the default graph parses
     * exactly as before.
     */
    public static Model parse(byte[] data, Lang lang, String baseIri) {
        DatasetGraph dsg = DatasetGraphFactory.create();
        try {
            RDFDataMgr.read(dsg, new ByteArrayInputStream(data), baseIri, lang);
        } catch (RiotException e) {
            throw new IllegalArgumentException("Malformed RDF: " + e.getMessage(), e);
        }
        requireNoNamedGraphData(dsg);
        Model m = ModelFactory.createDefaultModel();
        m.add(ModelFactory.createModelForGraph(dsg.getDefaultGraph()));
        m.setNsPrefixes(dsg.prefixes().getMapping());
        return m;
    }

    /** Refuse a document whose data does not all live in the default graph. */
    private static void requireNoNamedGraphData(DatasetGraph dsg) {
        List<String> named = new ArrayList<>();
        dsg.listGraphNodes().forEachRemaining(g -> {
            if (!dsg.getGraph(g).isEmpty()) {
                named.add(describe(g));
            }
        });
        if (!named.isEmpty()) {
            throw new IllegalArgumentException(
                    "This resource holds a single RDF graph, so named graph data cannot be stored: "
                            + String.join(", ", named));
        }
    }

    private static String describe(Node graphName) {
        return graphName.isURI() ? graphName.getURI() : graphName.toString();
    }

    public static byte[] write(Model model, RDFFormat format) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        RDFDataMgr.write(out, model, format);
        return out.toByteArray();
    }

    public static String writeString(Model model, RDFFormat format) {
        return new String(write(model, format), StandardCharsets.UTF_8);
    }
}
