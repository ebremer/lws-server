package com.ebremer.lws.server.rdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.riot.RiotException;

/**
 * Thin helpers for parsing and serializing RDF models to/from bytes.
 *
 * @author Erich Bremer
 */
public final class RdfIO {

    private RdfIO() {
    }

    /** Parse bytes into a new model, resolving relative IRIs against {@code baseIri}. */
    public static Model parse(byte[] data, Lang lang, String baseIri) {
        Model m = ModelFactory.createDefaultModel();
        try {
            RDFDataMgr.read(m, new ByteArrayInputStream(data), baseIri, lang);
        } catch (RiotException e) {
            throw new IllegalArgumentException("Malformed RDF: " + e.getMessage(), e);
        }
        return m;
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
