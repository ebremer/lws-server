package com.ebremer.lws.server.rdf;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;
import org.apache.jena.query.Dataset;
import org.apache.jena.rdfconnection.RDFConnection;
import org.apache.jena.system.Txn;
import org.apache.jena.tdb2.TDB2Factory;

/**
 * {@link RdfStore} backed by a local, transactional Apache Jena TDB2 dataset. This is the
 * default metadata store. Each unit of work runs in a real ACID transaction.
 *
 * @author Erich Bremer
 */
public final class Tdb2RdfStore implements RdfStore {

    private final Dataset dataset;

    public Tdb2RdfStore(Path location) {
        try {
            Files.createDirectories(location);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot create TDB2 directory: " + location, e);
        }
        this.dataset = TDB2Factory.connectDataset(location.toString());
    }

    public Tdb2RdfStore(Dataset dataset) {
        this.dataset = dataset;
    }

    /** The underlying dataset, e.g. to share with an embedded SPARQL (Fuseki) endpoint. */
    public Dataset dataset() {
        return dataset;
    }

    @Override
    public <T> T read(Function<RDFConnection, T> action) {
        RDFConnection conn = RDFConnection.connect(dataset);
        try {
            return Txn.calculateRead(conn, () -> action.apply(conn));
        } finally {
            conn.close();
        }
    }

    @Override
    public <T> T write(Function<RDFConnection, T> action) {
        RDFConnection conn = RDFConnection.connect(dataset);
        try {
            return Txn.calculateWrite(conn, () -> action.apply(conn));
        } finally {
            conn.close();
        }
    }

    @Override
    public void close() {
        dataset.close();
    }
}
