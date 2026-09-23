---
title: Architecture
nav_order: 3
---

# Architecture
{: .no_toc }

1. TOC
{:toc}

## Design goal: Spring is only a bootstrapper

The server is deliberately structured so that **Spring Boot is only a bootstrapper** and can be
removed later in favour of a bare Eclipse Jetty deployment:

- Every piece of protocol logic is a plain Jakarta `HttpServlet`/`Filter` or a framework-free service
  object. None of it imports Spring.
- The entire object graph is wired by one annotation-free factory, `LwsComponents`.
- The **only** Spring-aware classes are `LwsServer` (the `@SpringBootApplication` main) and
  `LwsServletConfig` (one `@Configuration` that registers the servlets/filters).
- `JettyLauncher` is a **no-Spring** `main` that registers the very same servlets/filters on a
  hand-built Jetty `Server` — the line-for-line analogue of `LwsServletConfig`. Migrating off Spring
  is: delete those two Spring classes and ship `JettyLauncher`.

The bare-Jetty launcher is also the only path that can [terminate TLS itself](deployment.md) (the
Spring entry point is intended for the reverse-proxy model).

## Package map

```
com.ebremer.lws.server
├─ LwsServer            @SpringBootApplication main (Spring – bootstrap only)
├─ LwsServletConfig     @Configuration: registers servlets/filters (Spring – bootstrap only)
├─ JettyLauncher        bare Eclipse Jetty main (no Spring) – the migration target
├─ LwsComponents        framework-free wiring of the whole object graph
├─ LwsConfiguration     immutable config POJO (no framework deps)
├─ vocab/               LWS, Activity Streams 2.0, LDP vocabularies (Apache Jena)
├─ rdf/                 RdfStore abstraction; Tdb2RdfStore + RemoteSparqlRdfStore; formats/IO
├─ storage/             BinaryStore abstraction + FileSystemBinaryStore (non-RDF bytes)
├─ core/                resource model, ResourceService (the protocol engine), registry,
│                       storage description, access policy, IRIs/etags
├─ auth/                credential validators, DPoP, Shiro realm/filter, WAC, SSRF guard
├─ notifications/       subscriptions, webhook dispatch, RFC 9421 signatures, Ed25519 keys
├─ tls/                 ACME (Let's Encrypt) certificate provisioning for the bare-Jetty launcher
├─ http/                the Jakarta servlets (resource, storage-description, subscriptions, jwks)
└─ ui/                  Apache Wicket storage browser
```

## Metadata store (pluggable SPARQL backend)

All RDF goes through `RdfStore`, which hands the service layer a Jena `RDFConnection`. Jena
implements that connection identically over a local TDB2 dataset and over any remote SPARQL 1.1
service (Query + Update + Graph Store Protocol), so the backend is a one-line wiring choice
(`lws.sparql.mode`):

- **TDB2** (default) — embedded, transactional, zero-ops.
- **Remote SPARQL** — point at Fuseki, GraphDB, Blazegraph, Neptune, … (see [Configuration](configuration.md)).

### What is stored where

- **RDF resource content** — one **named graph per resource**, named by the resource IRI.
- **Non-RDF resource content** — opaque bytes in a `BinaryStore` (filesystem by default), with the
  resource's metadata (media type, size, SHA-256 digest, binary key) in the RDF store.
- **Administrative metadata** — type, containment, timestamps, etags, owner, and pointers live in a
  dedicated `urn:x-lws:admin` graph, separate from content graphs.
- **Other internal graphs** — user-managed linkset metadata, subscriptions, access grants, and
  per-resource WAC ACLs each live in their own named graph.

This separation keeps content graphs pure RDF (exactly what the client wrote) while the server's
bookkeeping never mixes in.

## Request flow

1. **`AuthenticationFilter`** establishes the principal from the `Authorization` (and `DPoP`)
   headers — see [Authentication](authentication.md) — and binds it to a Shiro subject and a
   thread-local `RequestContext` (carrying the request `Origin` and any declared purposes). It is
   pass-through: it identifies the caller but does not itself authorize.
2. The matching **servlet** (`LwsResourceServlet` for the resource space, plus dedicated servlets for
   the storage description, subscriptions, JWKS, search and access services) handles the method.
3. **`ResourceService`** — the protocol engine — performs the operation transactionally against the
   `RdfStore` and `BinaryStore`, consulting the configured **`Authorizer`** (owner-based or WAC, with
   access grants layered on top) for every access decision, and emits resource events.
4. **Event listeners** (the notification emitter, the linkset metadata janitor, the search index, and
   the WAC ACL janitor) react to those events.

Because authorization is decided in the service layer, the HTTP servlets, the Wicket UI, and the
search services all enforce exactly the same rules.
