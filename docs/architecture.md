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

The bare-Jetty launcher is also the only path that can [terminate TLS itself](deployment.md); the
Spring entry point serves plain HTTP and is meant for the reverse-proxy model (it warns if
`lws.tls.enabled` is set).

## Package map

```
com.ebremer.lws.server
├─ LwsServer            @SpringBootApplication main (Spring – bootstrap only)
├─ LwsServletConfig     @Configuration: registers servlets/filters (Spring – bootstrap only)
├─ JettyLauncher        bare Eclipse Jetty main (no Spring) – the migration target
├─ LwsComponents        framework-free wiring of the whole object graph
├─ LwsConfiguration     immutable, validating config POJO (no framework deps)
├─ vocab/               LWS, CID, ACL, Activity Streams 2.0, LDP, FOAF, vCard vocabularies (Jena)
├─ rdf/                 RdfStore abstraction; Tdb2RdfStore + RemoteSparqlRdfStore (experimental,
│                       no transactions); formats/IO, JSON-LD guard, embedded Fuseki endpoint
├─ storage/             BinaryStore abstraction + FileSystemBinaryStore (non-RDF bytes)
├─ core/                resource model, ResourceService (the protocol engine), registry, storage
│                       description, Authorizer, access requests/grants, linksets, search index
├─ auth/                AuthenticationFilter; credential suites (OpenID, SSI-CID, did:key, SAML);
│                       AccessTokenValidator; DPoP; audience policy; owner, WAC and grant
│                       authorizers; OutboundFetchPolicy (SSRF guard); pac4j UI login
├─ oauth/               the embedded authorization server: token exchange (RFC 8693), RFC 9068
│                       access-token keys, token endpoint and RFC 8414 metadata servlets
├─ notifications/       subscriptions, webhook dispatch, RFC 9421 signatures, Ed25519 keys
├─ http/                the Jakarta servlets: resource, storage description, subscriptions, JWKS,
│                       access requests/grants, type index/search; CORS filter; digest fields
├─ tls/                 self-terminated HTTPS for JettyLauncher: ACME (HTTP-01) certificates and
│                       challenge servlet, HTTP→HTTPS redirect, HSTS filter
├─ tools/               DidKeyTool: mint a did:key credential (bootstrapping the first owner)
└─ ui/                  Apache Wicket storage browser
```

## Metadata store (pluggable SPARQL backend)

All RDF goes through `RdfStore`, which hands the service layer a Jena `RDFConnection`. Jena
implements that connection identically over a local TDB2 dataset and over any remote SPARQL 1.1
service (Query + Update + Graph Store Protocol), so the backend is a one-line wiring choice
(`lws.sparql.mode`):

- **TDB2** (default) — embedded, transactional, zero-ops.
- **Remote SPARQL** (**experimental**) — point at Fuseki, GraphDB, Blazegraph, Neptune, … (see
  [Configuration](configuration.md)).

> **Remote SPARQL has no transactions**, and the server refuses to start in that mode until you set
> `lws.sparql.remote.accept-no-transactions=true`. A unit of work becomes a sequence of independent
> requests that nothing rolls back: `If-Match` stops being a compare-and-swap, a delete no longer
> removes the resource's ACL and linkset atomically with it, binary content and its metadata can
> diverge, and the quota becomes advisory. TDB2 has none of these properties.
{: .warning }

### What is stored where

- **RDF resource content** — one **named graph per resource**, named by the resource IRI.
- **Non-RDF resource content** — opaque bytes in a `BinaryStore` (filesystem by default), with the
  resource's metadata (media type, size, SHA-256 digest, binary key) in the RDF store. Blob keys are
  opaque and server-generated, not derived from the path (IRIs are case-sensitive, many filesystems
  are not). A new version is written to a fresh key and the old bytes are unlinked only after the
  metadata naming the new ones has committed.
- **Administrative metadata** — type, containment, timestamps, etags and pointers live in the
  dedicated `urn:x-lws:admin` graph, separate from content graphs.
- **Other internal graphs** — WAC ACLs (in the `urn:x-lws:acl:` namespace, plus `urn:x-lws:acl-meta`),
  user-managed linkset metadata (`urn:x-lws:linkset`), subscriptions (`urn:x-lws:subscriptions`) and
  access requests/grants (`urn:x-lws:access`) each live in their own graphs.
- **Keys** — the webhook signing key and the access-token signing key live owner-only in
  `<data-dir>/keys/`.

This separation keeps content graphs pure RDF (exactly what the client wrote) while the server's
bookkeeping never mixes in.

## Request flow

1. **`HstsFilter`** and **`CorsFilter`** run first. The CORS filter answers a preflight itself, ahead
   of authentication, with a fixed method and header set.
2. **`AuthenticationFilter`** establishes the principal from the `Authorization` (and `DPoP`)
   headers — an access token checked by `AccessTokenValidator`, or a credential routed to its suite;
   see [Authentication](authentication.md) — and exposes it as a request attribute, with a
   thread-local `RequestContext` carrying the request `Origin` and any declared `LWS-Purpose`. It
   identifies the caller but does not authorize; a missing credential proceeds anonymously, an
   invalid one is answered `401` with the `as_uri`/`realm` challenge.
3. The matching **servlet** handles the method: `LwsResourceServlet` for the resource space (the
   storage URI `/` answers with the storage description unless a container representation is asked
   for), plus dedicated servlets for the storage description, the token endpoint and its RFC 8414
   metadata, subscriptions, JWKS, type index/search and the access services. The Wicket UI runs
   under `/app` (its pac4j OIDC login at `/app/oidc-login`, the callback at `/callback`).
4. **`ResourceService`** — the protocol engine — performs the operation transactionally against the
   `RdfStore` and `BinaryStore`, consulting the configured **`Authorizer`** (owner or WAC, with the
   grant authorizer layered on top) for every access decision. On delete, registered **cleanups**
   (the resource's ACL and linkset) run in the same transaction, so a failure aborts the delete.
5. **Event listeners** — the notification emitter and the search index — react to the committed
   resource events.

Because authorization is decided in the service layer, the HTTP servlets, the Wicket UI, and the
search services all enforce exactly the same rules. There is no session-based security framework in
the request path: Apache Shiro was removed, and authorization is decided by `Authorizer` from the
resource IRI and the required mode.
