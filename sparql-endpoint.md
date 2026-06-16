---
title: SPARQL Endpoint
nav_order: 11
---

# SPARQL Endpoint
{: .no_toc }

1. TOC
{:toc}

For administrative/analytical access, an embedded
[Apache Jena Fuseki](https://jena.apache.org/documentation/fuseki2/) SPARQL endpoint can be exposed
over the live TDB2 dataset (`lws.sparql.endpoint.enabled=true`, local `TDB2` backend only). It runs
as its own lightweight server on `lws.sparql.endpoint.port`, sharing the same dataset — so it sees
committed data immediately:

```bash
curl --data-urlencode 'query=SELECT (COUNT(*) AS ?n) WHERE { GRAPH ?g { ?s ?p ?o } }' \
     -H 'Accept: application/sparql-results+json' http://localhost:3030/lws/sparql
```

When enabled it is advertised in the [storage description](http-api.md#discovery--the-storage-description)
as a service whose `type` is the W3C SPARQL Service Description `Service` class
(`http://www.w3.org/ns/sparql-service-description#Service`) and whose `serviceEndpoint` is
`lws.sparql.endpoint.public-url` (or a URL derived from the base host, port and dataset) — so clients
can discover it like any other LWS service.

{: .warning }
> **This endpoint bypasses authorization.** It operates on the whole dataset, so it bypasses
> WAC/owner authorization and exposes the internal administrative graphs (resource registry, ACLs,
> subscriptions, access grants, linkset metadata). It is **disabled by default**, and when enabled is
> **query-only** (`read-only`) and bound to **loopback** unless reconfigured. Treat it as a trusted
> endpoint — keep it loopback-only or behind a trusted reverse proxy.

## SPARQL Update via PATCH

Separately from this endpoint, an RDF resource can be edited with SPARQL 1.1 Update through a
`PATCH` with `Content-Type: application/sparql-update` (see the [HTTP API](http-api.md)). That path is
fully access-controlled, and its `LOAD` / `SERVICE` operations — which would make the server fetch a
URL (an SSRF vector) — are blocked unless the target host is in `lws.sparql-update.allowed-hosts`
(empty by default ⇒ blocked entirely). See [Security](security.md).
