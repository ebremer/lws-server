package com.ebremer.lws.server.rdf;

import org.apache.jena.fuseki.main.FusekiServer;
import org.apache.jena.query.Dataset;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * An optional, embedded Apache Jena Fuseki server exposing a SPARQL endpoint over the server's
 * <em>live</em> local dataset (it shares the same TDB2 {@code DatasetGraph}, so it sees committed
 * data immediately and participates in the same transactions). It runs as its own lightweight Jetty
 * on a separate port, so it is independent of whichever container hosts the LWS servlets.
 *
 * <p><strong>Security.</strong> This endpoint operates on the whole dataset and therefore
 * <em>bypasses</em> per-resource Web Access Control / owner authorization and exposes the internal
 * administrative graphs (resource registry, ACLs, subscriptions, access grants, linkset metadata).
 * It is disabled by default; when enabled it is query-only and bound to loopback unless configured
 * otherwise. Treat it as a trusted/administrative endpoint: keep it loopback-only or behind a
 * trusted reverse proxy.
 *
 * @author Erich Bremer
 */
public final class FusekiSparqlServer implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(FusekiSparqlServer.class);

    private final FusekiServer server;
    private final LwsConfiguration config;

    public FusekiSparqlServer(Dataset dataset, LwsConfiguration config) {
        this.config = config;
        this.server = FusekiServer.create()
                .port(config.sparqlEndpointPort())
                .loopback(config.sparqlEndpointLoopback())
                .add(config.sparqlEndpointDataset(), dataset.asDatasetGraph(), !config.sparqlEndpointReadOnly())
                .build();
    }

    public void start() {
        server.start();
        log.warn("Embedded SPARQL endpoint listening on port {} at {}/sparql ({}{}). It bypasses "
                + "WAC/owner authorization and exposes ALL graphs (including internal admin/ACL/grant "
                + "metadata) — keep it loopback-only or behind trusted auth.",
                config.sparqlEndpointPort(), config.sparqlEndpointDataset(),
                config.sparqlEndpointReadOnly() ? "read-only" : "READ-WRITE",
                config.sparqlEndpointLoopback() ? ", loopback only" : ", ALL interfaces");
    }

    @Override
    public void close() {
        server.stop();
    }
}
