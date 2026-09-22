# LWS Server

A [Linked Web Storage](https://w3c.github.io/lws-protocol/) server implementing the W3C LWS
Protocol, written as plain Jakarta servlets and bootstrapped (for now) by Spring Boot on an
embedded Eclipse Jetty container.

It implements:

- **[LWS Core](https://w3c.github.io/lws-protocol/lws10-core/)** — the resource/containment model and CRUD operations.
- **[LWS Vocabulary](https://w3c.github.io/lws-protocol/lws10-vocab/)** — the `https://www.w3.org/ns/lws#` terms.
- **[LWS Authorization](https://w3c.github.io/lws-protocol/lws10-core/#authorization)** — the OAuth 2.0
  baseline: an embedded authorization server (Token Exchange, RFC 8693; metadata at
  `/.well-known/lws-configuration`) issuing RFC 9068 access tokens for this storage, the storage's
  validation of those tokens (and of trusted external servers'), and `as_uri`/`realm` challenges.
- **Authentication suites** — the three current LWS suites:
  [OpenID Connect](https://w3c.github.io/lws-protocol/lws10-authn-openid/),
  [SAML 2.0](https://w3c.github.io/lws-protocol/lws10-authn-saml/), and
  [Self-signed Controlled Identifier](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/), which
  covers HTTPS, `did:key` and `did:web` subjects. The
  [self-signed did:key](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/) suite it
  replaced was discontinued on 18 September 2026; its credentials are still accepted, deprecated.
- **[LWS Notifications](https://w3c.github.io/lws-protocol/lws10-core/#notifications)** — the core
  notification data model and the [webhook suite](https://w3c.github.io/lws-protocol/lws10-notifications-webhook/),
  with RFC 9421 HTTP Message Signatures verifiable from the storage description.
- **[LWS Search & Type Index](https://w3c.github.io/lws-protocol/lws10-index/)** — the `TypeIndexService` and the `QUERY`-based `TypeSearchService` (authorization-filtered).
- **[Access Requests & Grants](https://w3c.github.io/lws-protocol/lws10-core/#access-requests-and-grants)** — ODRL-based `AccessRequestService`/`AccessGrantService`; grants are enforced and revocable.

> **Specification baseline:** the LWS editor's drafts as of **21 September 2026**
> (`w3c/lws-protocol` @ `3ddc642`). See [COMPLIANCE.md](COMPLIANCE.md) for what changed since the
> previous baseline and where this server departs from the drafts, deliberately. Where the drafts
> are still silent this implementation follows the **LDP / Solid Protocol conventions** it derives
> from (trailing-slash containers, `Link: rel="type"` interaction models, content negotiation,
> conditional requests).

## Design goals

This server is deliberately structured so that **Spring Boot is only a bootstrapper** and can be
removed later in favour of a bare Eclipse Jetty deployment:

- Every piece of protocol logic is a plain Jakarta `HttpServlet`/`Filter` or a framework-free
  service object. None of it imports Spring.
- The entire object graph is wired by one annotation-free factory,
  [`LwsComponents`](src/main/java/com/ebremer/lws/server/LwsComponents.java).
- The **only** Spring-aware classes are
  [`LwsServer`](src/main/java/com/ebremer/lws/server/LwsServer.java) (the `@SpringBootApplication`
  main) and [`LwsServletConfig`](src/main/java/com/ebremer/lws/server/LwsServletConfig.java)
  (one `@Configuration` that registers the servlets/filters).
- [`JettyLauncher`](src/main/java/com/ebremer/lws/server/JettyLauncher.java) is a **no-Spring**
  `main` that registers the very same servlets/filters on a hand-built Jetty `Server` — the
  line-for-line analogue of `LwsServletConfig`. Migrating off Spring is: delete those two Spring
  classes and ship `JettyLauncher`.

## Architecture

```
com.ebremer.lws.server
├─ LwsServer            @SpringBootApplication main (Spring – bootstrap only)
├─ LwsServletConfig     @Configuration: registers servlets/filters (Spring – bootstrap only)
├─ JettyLauncher        bare Eclipse Jetty main (no Spring) – the migration target
├─ LwsComponents        framework-free wiring of the whole object graph
├─ LwsConfiguration     immutable config POJO (no framework deps)
├─ vocab/               LWS, Activity Streams 2.0, LDP vocabularies (Apache Jena)
├─ rdf/                 RdfStore abstraction; Tdb2RdfStore + RemoteSparqlRdfStore (experimental,
│                       no transactions); formats/IO
├─ storage/             BinaryStore abstraction + FileSystemBinaryStore (non-RDF bytes)
├─ core/                resource model, ResourceService (the protocol engine), registry,
│                       storage description, access policy, IRIs/etags
├─ auth/                LWS OpenID validator (Nimbus), authentication filter, pac4j UI login
├─ notifications/       subscriptions, webhook dispatch, RFC 9421 signatures, Ed25519 keys
├─ tls/                 self-terminated HTTPS: ACME (HTTP-01) certificate manager and challenge
│                       servlet, HTTP→HTTPS redirect. Used by JettyLauncher only — see the note
│                       under Deployment about the Spring Boot entry point
├─ tools/               DidKeyTool: mint a did:key credential for testing and for bootstrapping
├─ http/                the Jakarta servlets: resource, storage-description, subscriptions, jwks,
│                       access requests/grants, search index; plus HttpSupport and DigestFields
└─ ui/                  Apache Wicket storage browser
```

### Metadata store (pluggable SPARQL backend)

All RDF goes through [`RdfStore`](src/main/java/com/ebremer/lws/server/rdf/RdfStore.java), which
hands the service layer a Jena `RDFConnection`. Jena implements that connection identically over
a local TDB2 dataset and over any remote SPARQL 1.1 service (Query + Update + Graph Store
Protocol), so the backend is a one-line wiring choice:

- **TDB2** (default) — embedded, transactional, zero-ops.
- **Remote SPARQL** (**experimental**) — point at Fuseki, GraphDB, Blazegraph, Neptune, … (see
  config below).

> **Remote SPARQL has no transactions, and the server refuses to start in that mode until you say
> you know.** Set all three of `lws.sparql.query` / `.update` / `.gsp` and
> `lws.sparql.remote.accept-no-transactions=true`. Remote SPARQL has no cross-statement transaction
> concept, so a unit of work is a sequence of independent requests that nothing rolls back. What
> that costs, concretely: a conditional write's `If-Match` stops being a compare-and-swap, so two
> clients holding the same entity-tag can both succeed and the second silently discards the first;
> a delete no longer erases the resource's ACL and linkset atomically with it, so a path re-created
> afterwards can inherit the old ACL; binary content and the metadata describing it are committed
> separately and can diverge; the linkset read-modify-write and the storage quota become advisory;
> and two concurrent `POST`s with the same `Slug` can pick the same name. The default TDB2 backend
> has none of these properties.

Resource content is stored as **one named graph per RDF resource**; non-RDF resources are stored
as opaque bytes by a [`BinaryStore`](src/main/java/com/ebremer/lws/server/storage/BinaryStore.java)
(filesystem by default), with their metadata in the RDF store. Blob keys are **opaque and
server-generated**, not derived from the resource path: IRIs are case-sensitive while NTFS and
default APFS/HFS+ are not, so path-derived keys let two distinct resources collide onto one file.
An opaque key also means every new version is written somewhere no reader can reach yet, so the
superseded bytes are unlinked only once the metadata naming the new ones has committed — a rolled
back or crashed write can leak an unreferenced blob, but never leave a resource pointing at bytes
that are gone. Administrative metadata (type, containment, timestamps, etags, ACL, subscriptions)
lives in dedicated named graphs.

## Build

```bash
mvn -DskipTests package
```

Requires **JDK 25**: `maven.compiler.release=25`, so the build emits class-file major version 69 and will not load on anything earlier. Produces an executable `target/lws-server.jar`.

## Run

### Spring Boot (default)

```bash
java -jar target/lws-server.jar
# or
mvn spring-boot:run
```

### Bare Eclipse Jetty (no Spring)

```bash
mvn dependency:build-classpath -Dmdep.outputFile=target/cp.txt
java -cp "target/classes:$(cat target/cp.txt)" com.ebremer.lws.server.JettyLauncher
```

The server listens on the port in `lws.base-uri` (default `http://localhost:8080`).

## Configuration

Configuration is resolved from built-in defaults, then `lws.properties` (classpath or working
directory), then `-Dlws.*` system properties. See
[`lws.example.properties`](lws.example.properties). Invalid values **fail fast** at startup with an
actionable message naming the key, the value, and what was expected (e.g. an out-of-range port, an
unknown enum, a non-`true`/`false` flag, or a malformed `lws.base-uri`) rather than a raw parse
exception. Key settings:

| Property | Default | Meaning |
|---|---|---|
| `lws.base-uri` | `http://localhost:8080` | Public base IRI; also sets the listen port |
| `lws.data-dir` | `lws-data` | Directory for TDB2, blobs and keys |
| `lws.owners` | *(empty)* | Space/comma-separated owner WebIDs. **Empty ⇒ refuses to start** unless `lws.dev.open=true` |
| `lws.dev.open` | `false` | Permit development-only postures: empty `lws.owners` (open mode) and `lws.ui.dev-login` off-loopback |
| `lws.public-read` | `false` | Whether non-owners may read the storage **at all** — storage-wide, not per resource |
| `lws.access-control` | `OWNER` | `OWNER` (single-tenant) or `WAC` (multi-user Web Access Control) |
| `lws.wac.group-cache-seconds` | `300` | WAC: how long a resolved `acl:agentGroup` membership set is reused |
| `lws.wac.group-failure-cache-seconds` | `30` | WAC: how long an unresolvable group document is left alone before a retry |
| `lws.wac.max-group-fetches-per-decision` | `8` | WAC: group documents one authorization decision may dereference |
| `lws.sparql.mode` | `TDB2` | `TDB2`, or `REMOTE` (experimental — see below) |
| `lws.sparql.query` / `.update` / `.gsp` | | **Required** when `mode=REMOTE`; absolute `http(s)` URLs |
| `lws.oidc.discovery-uri` / `.client-id` / `.client-secret` | | Enable interactive OIDC login for the UI |
| `lws.ui.dev-login` | `false` | Enable the UI's developer sign-in (impersonation; **dev only**; loopback base URI only, and refused per request off-loopback or behind a proxy) |
| `lws.saml.idp-certificates` | | PEM/DER X.509 cert paths of trusted SAML IdPs (enables the SAML suite) |
| `lws.saml.trusted-issuers` / `lws.saml.audience` | | Optional SAML issuer allow-list / expected audience |
| `lws.webhook.max-attempts` | `5` | Webhook delivery attempts, for *retryable* outcomes only (5xx, 429, transient I/O) |
| `lws.webhook.retry-backoff-ms` | `2000` | Backoff between attempts, multiplied by the attempt number; scheduled, not slept |
| `lws.system-prefix` | `/.lws` | Path prefix for the server's own endpoints. Reserved: no resource may be created under it |
| `lws.webhook.threads` / `lws.webhook.queue-capacity` | `4` / `1000` | Delivery workers, and how many deliveries may wait for one before being dropped |
| `lws.webhook.max-in-flight-per-host` | `4` | Deliveries in flight to one inbox host, so a slow subscriber cannot occupy the pool |
| `lws.subscription.purge-interval-seconds` | `3600` | How often expired subscriptions are purged (0 disables) |
| `lws.webhook.max-consecutive-failures` | `10` | Failures before a subscription is deactivated |
| `lws.search-index.enabled` | `true` | Advertise and serve the Type Index / Type Search services |
| `lws.search-index.page-size` | `100` | Max items per Type Index / Type Search response page |
| `lws.container.page-size` | `1000` | Max members per container-listing page (larger listings are paginated) |
| `lws.access-requests.enabled` | `true` | Advertise and serve the Access Request / Access Grant services |
| `lws.access-requests.controller-inbox` | | Inbox notified when a new access request is created |
| `lws.quota.max-bytes` | `0` | Max total binary-content bytes (`0` = unlimited); over-quota writes get `507` |
| `lws.max-request-bytes` | `67108864` | Max request-body size (`0` = unlimited); larger requests get `413` |
| `lws.audience` | this storage's IRI | Accepted `aud` values for JWT credentials (comma/space separated) |
| `lws.audience.require` | `true` | Require an `aud` claim; a wrong `aud` is refused regardless |
| `lws.token.max-lifetime-seconds` | `3600` | Max lifetime of a self-signed (SSI-CID, including did:key) credential (`0` = unlimited) |
| `lws.oauth.enabled` | `true` | Run the embedded authorization server: token endpoint `<system-prefix>/token`, metadata `/.well-known/lws-configuration` |
| `lws.oauth.access-token-lifetime-seconds` | `300` | Lifetime of the access tokens it issues (1–3600; never longer than the exchanged credential) |
| `lws.oauth.trusted-issuers` | | External authorization servers whose RFC 9068 access tokens are also accepted |
| `lws.oauth.accept-authentication-credentials` | `true` | Also accept an authentication credential presented directly (the pre-baseline behaviour) |
| `lws.notifications.include-actor` | `false` | Name the agent that made a change in notifications (lws10-core: omit by default) |
| `lws.dpop.require-nonce` | `false` | Require a server-issued nonce in DPoP proofs (RFC 9449 §8) |
| `lws.dpop.require` | `false` | Refuse plain `Bearer` entirely (a `cnf.jkt` token is always refused there) |
| `lws.dpop.jti-cache-size` | `100000` | Retained DPoP proof ids; a size eviction re-opens a replay window, so size it above peak DPoP requests per acceptance window |
| `lws.ssi-cid.document-cache-seconds` | `300` | How long an SSI-CID subject document is reused (also the window in which a revoked key stays honoured) |
| `lws.ssi-cid.document-failure-cache-seconds` | `30` | How long an unreachable SSI-CID subject is left alone before a retry |
| `lws.sparql.remote.accept-no-transactions` | `false` | Required to run `lws.sparql.mode=REMOTE`, which has no transactions (see Deployment) |
| `lws.sparql-update.allowed-hosts` | | Hosts a SPARQL Update `LOAD`/`SERVICE` may fetch (empty = blocked) |
| `lws.fetch.block-private-addresses` | `true` | Block auth/WAC dereferences to private/loopback/metadata addresses (SSRF guard) |
| `lws.fetch.allowed-hosts` | | Hosts exempt from that block (e.g. an internal IdP) |
| `lws.webhook.block-private-addresses` | `true` | Block notification delivery to private/loopback/metadata inbox addresses |
| `lws.webhook.allowed-hosts` | | Inbox hosts exempt from that block (e.g. an internal consumer) |
| `lws.subscriptions.allow-anonymous` | `false` | Allow unauthenticated subscription creation |
| `lws.subscriptions.max-per-subscriber` | `100` | Subscriptions one subscriber may hold (further creates get `429`) |
| `lws.subscriptions.max-lifetime-seconds` | `2592000` | Max/default subscription lifetime (`0` = no expiry imposed) |
| `lws.jsonld.allowed-context-hosts` | | Hosts whose JSON-LD `@context` may be fetched (empty = remote contexts refused) |
| `lws.sparql.endpoint.enabled` | `false` | Expose an embedded Fuseki SPARQL endpoint over the local dataset |
| `lws.sparql.endpoint.port` / `.dataset` / `.read-only` / `.loopback` | `3030` / `lws` / `true` / `true` | SPARQL endpoint port, dataset path, query-only, loopback-only |
| `lws.sparql.endpoint.public-url` | | Query URL advertised in the storage description (else derived from base host/port) |
| `lws.behind-proxy` | `false` | Trust `X-Forwarded-*` / `Forwarded` (RFC 7239) from a fronting TLS-terminating proxy |
| `lws.require-https` | `false` | Refuse to start unless `lws.base-uri` is `https://` (loopback exempt) |
| `lws.hsts.max-age-seconds` | `31536000` | `Strict-Transport-Security` lifetime, sent only on TLS responses of an `https` base URI (`0` = off) |
| `lws.cors.allowed-origins` | | Web origins allowed to call the API from a browser (empty = no cross-origin access; `*` refused in open mode) |
| `lws.cors.max-age-seconds` | `600` | How long a browser may cache a CORS preflight |
| `lws.tls.enabled` | `false` | Terminate TLS in the server, provisioning a cert via ACME (bare-Jetty launcher) |
| `lws.tls.port` / `lws.tls.http-port` | `443` / `80` | HTTPS port, and the HTTP port serving the ACME challenge + redirect |
| `lws.tls.acme.directory-url` | Let's Encrypt prod | ACME directory (e.g. `…/acme-staging-v02…/directory` for testing) |
| `lws.tls.acme.domains` | base-URI host | Domain(s) to certify (space/comma separated) |
| `lws.tls.acme.email` | | Contact email for the ACME account |
| `lws.tls.acme.accept-terms-of-service` | `false` | MUST be `true` to register (agrees to the CA's ToS) |
| `lws.tls.acme.renew-before-days` / `lws.tls.dir` | `30` / `<data>/tls` | Renewal lead time; directory for the account key, domain key, and cert |

> **Security note:** the server **refuses to start with no `lws.owners`**. An empty owner list is
> *open mode* — every read, write and control decision permitted for every client, anonymous
> included — and it is still available, but it has to be asked for with `lws.dev.open=true`. Open
> mode also has no storage *controller*: with nobody configured, nobody was entrusted with the
> storage, so access grants cannot be issued there at all.
>
> `lws.public-read` defaults to **false** and is storage-wide. To open one resource or one subtree to
> the world, issue an access grant with `assignee: foaf:Agent`; deleting it closes the access again
> on the next request.

### Running behind a reverse proxy (TLS)

The server terminates **plain HTTP** and does not do TLS itself; in production it is meant to sit
behind a reverse proxy (nginx, Caddy, Traefik, …) that terminates HTTPS. DPoP and WebID/OIDC assume
TLS, so:

1. Set `lws.base-uri` to the **external** `https://` URL — DPoP `htu`, WebIDs, ACLs and every minted
   IRI come from this value, not from the (internal) request scheme/host, so it works correctly even
   though the app speaks HTTP behind the proxy.
2. Set `lws.behind-proxy=true` so the server trusts `X-Forwarded-Proto`/`X-Forwarded-Host` /
   `Forwarded` (RFC 7239) from the proxy; this makes `request.isSecure()`, generated redirects and
   secure-cookie flags reflect the external HTTPS URL. Enable it **only** when a trusted proxy is in
   front and strips client-supplied forwarding headers (otherwise a client could spoof the scheme).
3. Set `lws.require-https=true` to fail fast if `base-uri` is not `https://` (loopback hosts stay
   exempt for local development).

Example nginx front end for a server on `127.0.0.1:8080`:

```nginx
server {
  listen 443 ssl;
  server_name storage.example;
  # ssl_certificate / ssl_certificate_key ...
  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;   # https
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
  }
}
```

### Terminating TLS in the server (ACME / Let's Encrypt)

As an alternative to a reverse proxy, the **bare-Jetty launcher** (`com.ebremer.lws.server.JettyLauncher`)
can terminate TLS itself, obtaining and renewing a certificate from an ACME CA (Let's Encrypt by
default) via [acme4j](https://acme4j.shredzone.org/) and the **HTTP-01** challenge. (The Spring Boot
entry point is intended for the reverse-proxy model above; TLS is wired into the bare launcher, the
project's intended deployment target.)

How it works: the launcher starts the HTTP connector (`lws.tls.http-port`, default `80`), provisions
the certificate (serving the challenge at `/.well-known/acme-challenge/*`), then starts the HTTPS
connector (`lws.tls.port`, default `443`). Plain-HTTP requests other than the challenge are redirected
to HTTPS. The account key, domain key, and certificate are cached under `lws.tls.dir`, so restarts
reuse a still-valid certificate; a daemon checks twice daily and renews within
`lws.tls.acme.renew-before-days` of expiry, hot-reloading the TLS context with no restart.

**Setup:**
1. Point DNS for your domain at the host, and make ports **80 and 443 publicly reachable** (the CA
   connects to port 80 to validate the HTTP-01 challenge). Run the launcher as a user permitted to
   bind those ports (e.g. `setcap`/`authbind`, a systemd socket, or root).
2. Configure (in `lws.properties` or via `-Dlws.*`):
   ```properties
   lws.base-uri=https://storage.example
   lws.tls.enabled=true
   lws.tls.acme.email=admin@storage.example
   lws.tls.acme.accept-terms-of-service=true     # required; agrees to the CA's Terms of Service
   # lws.tls.acme.domains=storage.example        # defaults to the lws.base-uri host
   # while testing, use the staging CA to avoid rate limits (its certs are NOT browser-trusted):
   # lws.tls.acme.directory-url=https://acme-staging-v02.api.letsencrypt.org/directory
   ```
3. Run the bare-Jetty launcher (it lives in the same jar):
   ```bash
   java -cp target/lws-server.jar -Dloader.main=com.ebremer.lws.server.JettyLauncher \
       org.springframework.boot.loader.launch.PropertiesLauncher
   # or from a source checkout:  mvn -q exec:java -Dexec.mainClass=com.ebremer.lws.server.JettyLauncher
   ```

**Notes:** start with the **staging** directory URL to validate the setup (Let's Encrypt production
has strict rate limits); switch to production once it works, deleting `lws.tls.dir` so a fresh,
trusted certificate is ordered. Use `lws.tls.enabled` **or** the reverse-proxy model, not both. Other
challenge types (TLS-ALPN-01, DNS-01) and non-Let's-Encrypt CAs are not wired up — point
`lws.tls.acme.directory-url` at any ACME CA that supports HTTP-01.

### Bootstrapping the first owner

`lws.owners` holds WebIDs/DIDs, but you need a *credential* for one before you can act as that
owner. A `did:key` subject of the
[self-signed controlled identifier](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/) suite
needs no identity provider — its DID document is derived from the identifier itself — so a bundled
helper can mint the very first owner offline:

```
# from the packaged fat jar
java -cp target/lws-server.jar -Dloader.main=com.ebremer.lws.server.tools.DidKeyTool \
     org.springframework.boot.loader.launch.PropertiesLauncher

# or, from a source checkout
mvn -q exec:java -Dexec.mainClass=com.ebremer.lws.server.tools.DidKeyTool
```

It prints (1) a `did:key:…` to drop into `lws.owners`, (2) a private-key seed to keep secret
(pass it back with `--key <seed>` to re-mint credentials for the same identity), and (3) a ready
credential — a self-issued JWT whose `kid` names the DID's verification method — to send as
`Authorization: Bearer <token>` or to exchange at `/.lws/token` for an access token. Options:
`--ttl <seconds>` (lifetime, default 3600) and `--audience <aud>`. Put the DID in `lws.owners`,
restart, and the credential authenticates you as that owner.

## HTTP API

| Method | Target | Behaviour |
|---|---|---|
| `GET`/`HEAD` | data resource | Content-negotiated representation (Turtle, JSON-LD, N-Triples, RDF/XML); binary streamed as-is, with byte-range support (`206`/`416`, `Accept-Ranges: bytes`) |
| `GET`/`HEAD` | `/` (the storage URI) | The **storage description** (`application/lws+cid`) unless the client asks for a container representation — `application/lws+json`, `application/ld+json`, `application/json` or an RDF type — in which case the root container listing below |
| `GET`/`HEAD` | container | `application/lws+json` listing (`id`/`type`/`totalItems`/`items[]` with `id`/`type`/`format`/`size`/`modified`, `type` naming any declared types after `DataResource`/`Container`); content-negotiable as `application/ld+json`/`application/json` (the requested `Content-Type` is echoed) or RDF; paginated (`?page=N`, `Link` rel=`first`/`prev`/`next`/`last`) above `lws.container.page-size` |
| `POST` | a container | Create a contained resource; `Slug` names it, `Link: rel="type"` picks container/RDF/non-RDF; `201` + `Location`. A reserved name is refused with `409` — see [Reserved names](#reserved-names) |
| `PUT` | any IRI | Create (new) or replace (existing) at that exact IRI; replacing MUST be conditional. A reserved path is refused with `409`; an existing container with `409` (its representation is its membership); a `Link: rel="type"` that contradicts the IRI's own shape with `400` |
| `PATCH` | RDF or JSON resource | RDF: `application/sparql-update`; JSON & linkset: `application/merge-patch+json` (RFC 7386) or `application/json-patch+json` (RFC 6902) |
| `DELETE` | any resource | Delete (non-empty container → `409`, or recursive with `Depth: infinity`); removes the resource's metadata too |
| `GET`/`HEAD`/`PATCH`/`PUT`/`OPTIONS` | `<resource>.meta` | The resource's linkset (metadata) resource — see [Metadata](#metadata-linkset) |
| `OPTIONS` | any | `Allow`, `Accept-Post`, `Accept-Patch`, `Want-Content-Digest` |
| `POST` | `<system-prefix>/token` | OAuth 2.0 Token Exchange (RFC 8693) at the embedded authorization server — see [Authentication](#authentication) |
| `GET` | `/.well-known/lws-configuration` | The embedded authorization server's metadata (RFC 8414) |

<a id="reserved-names"></a>
**Reserved names.** Four namespaces belong to the server, and no resource may be created or replaced
in them — `POST` with such a `Slug`, and `PUT` at such a path, are answered `409 Conflict`:

| Reserved | Owned by |
|---|---|
| any name ending `.acl` | the access-control resource of its target |
| any name ending `.meta` | the linkset (metadata) resource of its target |
| `lws.system-prefix` (default `/.lws`) and below | the storage description, JWKS, token endpoint, subscriptions, type index, access requests/grants |
| `/app` and `/callback` and below | the management console and the OIDC login callback |
| `/.well-known/lws-configuration` and `/.well-known/acme-challenge` and below | the authorization server metadata and the ACME HTTP-01 responder |

The request router already sends all of these elsewhere, so a resource created at one of those names was
unreachable by every HTTP method — and, before this was enforced, `POST` with `Slug: .acl` wrote the
graph governing access to the container it was posted to. The match ignores case and covers the
container form (`.acl/`), because reserving more than is routed away is free while reserving less is
a vulnerability. The name is tested exactly as sent, with no percent-decoding, so `x%2Eacl` is a
distinct and perfectly legal name.

A container's `ETag` is the value its own preconditions are evaluated against, and it changes
whenever the container's membership does — so `GET` a container, then `If-Match` that tag on a
`PUT`/`PATCH`/`DELETE`, and the conditional write behaves.

**Except from a numbered page.** A page is its own representation and carries its own tag, which
deliberately does *not* satisfy an `If-Match` on the container: a client that read page 2 has not
read the state a write would replace, and treating it as though it had is the lost update the
precondition exists to prevent. A listing that fits in one page (`lws.container.page-size`, 1000 by
default) is not paginated and its tag names the state directly; for a larger container, take the tag
from the RDF rendering (`Accept: text/turtle`), which is the full listing and is never paginated.

Container listings are authorization-filtered per client and are therefore sent
`Cache-Control: private, no-store`: the entity-tag is a concurrency token for writers, not a
validator a shared cache may key on.

`If-Match` is a compare-and-swap, not a check followed by a write. The tag is compared against the
stored one *inside* the transaction that makes the change, under the single writer the store admits,
so of two clients that both `GET` `"v1"` and both `PUT` with `If-Match: "v1"`, exactly one gets `204`
and the other gets `412`. The same holds for `PATCH`, `DELETE` and linkset writes. A precondition
against a resource that does not exist is never satisfied — including `If-Match: *` — so a `PUT`
naming a version it cannot find is refused with `412` rather than quietly creating the resource; an
unconditional `PUT` still creates. `ConditionalWriteTest` races eight writers at each of those paths.

Deleting a resource removes its content, its ACL and its linkset in one transaction. A path that is
deleted and later re-created therefore starts with no access-control state of its own, rather than
inheriting whatever the previous occupant's ACL granted.

A write that cannot be carried out is refused rather than partly performed. A `PUT` or `POST` that
would create or replace a **container** is `409` when it carries a body — a container's
representation *is* its membership, so there is nowhere for the triples to go — while a bodiless
conditional `PUT` to one that exists returns `204` and changes nothing, entity-tag included. A
**SPARQL Update that names a graph** (`GRAPH`, `WITH`, `USING`, or graph management) is `400`: a
resource is a single graph, and such an update used to execute against a throwaway one and report
`204`. That includes an update naming the resource's own IRI, which reads as the obvious thing to
write and never worked. A `Link: rel="type"` that contradicts the shape of the IRI it is sent to is `400`:
a container registered at a slash-less IRI would have its children land in the wrong parent. And a
request body carrying RDF outside the default graph — TriG with a `GRAPH` block, JSON-LD with a
named-graph node — is `400` rather than being stored with those quads quietly dropped.

Non-RDF resources keep the media type they were stored with, but are served defensively: every one
carries `X-Content-Type-Options: nosniff` and a `Content-Security-Policy: sandbox`, and anything a
browser would execute in this origin (`text/html`, `image/svg+xml`, `application/xhtml+xml`, XML)
additionally gets `Content-Disposition: attachment` so it downloads rather than renders. Storage is
written by one agent and read by another on the same origin as the `/app/` console, so uploaded
content is never allowed to become script in that origin. Serving user content from a separate
hostname remains the stronger arrangement if you can.

Responses carry `ETag`, `Last-Modified`, and `Link` relations: `rel="type"` — the interaction
models, `https://www.w3.org/ns/lws#Container`/`#DataResource`, and any type the resource's metadata
declares —, `rel="https://www.w3.org/ns/lws#storage"` to the storage URI (on every `GET` and `HEAD`
of a Storage Resource, linksets, ACLs and the server's own containers included), `rel="up"` (parent
container, non-root), and `rel="linkset"` (the metadata resource). `If-None-Match`/`If-Modified-Since`
(→ `304`) and `If-Match` (→ `412`) are honoured; an unconditional PUT replacing an existing resource is
refused with `428 Precondition Required`; a write exceeding `lws.quota.max-bytes` is refused with
`507 Insufficient Storage`. Errors are returned as `application/problem+json` (RFC 9457).

A `401` carries the lws10-core challenge — `WWW-Authenticate: Bearer as_uri="<authorization server>",
realm="<storage URI>"` (and the same for `DPoP`, with its `algs`) — and the link to the storage, so a
client learns where to get an access token and what to ask for without a hardcoded URI.

**The storage description** is a W3C controlled identifier document (lws10-core, Storage Description
Resource), served as `application/lws+cid` at the storage URI — this server's root URI, `/` — and at
`/.lws/storage-description`. Its `@context` is `["https://www.w3.org/ns/cid/v1",
"https://www.w3.org/ns/lws/v1"]`, its `id` the storage URI; it lists the `StorageRoot` service (the
root container) and the notification, search, access and SPARQL services, publishes the webhook
signing key as a `JsonWebKey` verification method referenced from `authentication`, and carries the
capabilities. Each `capability` is a **structured object** (`{type, …}`): the implemented
specifications (type only), a `PatchSupport` entry mapping each target format to its accepted PATCH
formats, one `ContentNegotiation` entry per RDF serialisation, and an RFC 9530 digest entry listing the
supported algorithms. `application/ld+json`, `application/json` and RDF are available via content
negotiation.

**Integrity (RFC 9530).** A request that carries a `Content-Digest` has its body verified before any
write — a mismatch or malformed field is rejected with `400`, and digest algorithms the server does
not support are ignored. Reads honour `Want-Repr-Digest`/`Want-Content-Digest` by emitting
`Repr-Digest`/`Content-Digest` (`sha-256`/`sha-512`, highest-weight preference, ties favouring the
stronger algorithm). Non-RDF resources serve a `Repr-Digest` from a SHA-256 persisted at write time
(so the blob is never re-read); `Content-Digest` is omitted on partial `206` range responses since it
would not describe the bytes actually sent. The server advertises that it accepts integrity-protected
writes by emitting `Want-Content-Digest` on `OPTIONS` and on write responses, and lists digest support
as a capability in the storage description.

### Metadata (linkset)

Every resource has a **linkset resource** at `<resource>.meta`
([RFC 9264](https://www.rfc-editor.org/rfc/rfc9264), `application/linkset+json`), discoverable via
the `rel="linkset"` Link header. It merges server-managed links (`type`, `up`, `linkset`, the
storage description) with user-managed links. Server-managed links cannot be overridden. The
user-managed portion is updated with `application/merge-patch+json` or `application/json-patch+json`
(or replaced with PUT); these writes are conditional — a missing `If-Match` is refused with `428`, a
stale one with `412`. A relation's value may be an RFC 9264 target array (`{"href": …}` objects, with
optional link attributes such as `title`) **or a literal** (a JSON string/array, e.g. a `title` or
`creator` label) — both round-trip, so literal-valued core metadata is supported.

Two preferences (RFC 7240) tune metadata writes and reads:
- **`Prefer: set-linkset`** on a resource PUT/PATCH applies that request's `Link` headers to the
  resource's linkset in the same operation (replace on PUT, partial update on PATCH), echoing
  `Preference-Applied: set-linkset`. Off unless the header is sent, so ordinary writes never touch
  metadata.
- **`Prefer: include="…"` / `omit="…"`** (the LWS *PreferLinkRelations* read preference; the spec
  leaves the wire syntax open, so this is the server's RFC 7240 encoding) returns only — or drops —
  the listed relations on a linkset read, keeping the structural `anchor`, and echoes
  `Preference-Applied`.

### Example

```bash
# create an RDF resource in the root container
curl -i -X POST -H 'Content-Type: text/turtle' -H 'Slug: greeting' \
     --data '<#it> <http://schema.org/name> "Hello LWS" .' http://localhost:8080/

# read it back as JSON-LD
curl -H 'Accept: application/ld+json' http://localhost:8080/greeting

# create a container, then patch a resource in it
curl -X PUT -H 'Link: <http://www.w3.org/ns/ldp#Container>; rel="type"' http://localhost:8080/box/
curl -X PUT -H 'Content-Type: text/turtle' --data '<#x> <http://schema.org/n> 1 .' http://localhost:8080/box/x
curl -X PATCH -H 'Content-Type: application/sparql-update' \
     --data 'INSERT DATA { <http://localhost:8080/box/x#x> <http://schema.org/age> 42 }' http://localhost:8080/box/x

# create a JSON resource, then partially update it with JSON Merge Patch (RFC 7386)
curl -X POST -H 'Content-Type: application/json' -H 'Slug: doc.json' \
     --data '{"a":1,"b":2}' http://localhost:8080/
curl -X PATCH -H 'Content-Type: application/merge-patch+json' \
     --data '{"b":null,"c":3}' http://localhost:8080/doc.json   # => {"a":1,"c":3}
```

### Authentication

**The baseline: access tokens (lws10-core, Authorization).** A client exchanges an authentication
credential for an access token at an authorization server, and presents the token to the storage.
This server embeds one (`lws.oauth.enabled`, on by default):

```bash
# what a 401 says: where to get a token (as_uri) and what for (realm)
curl -si http://localhost:8080/private | grep -i www-authenticate
#   WWW-Authenticate: Bearer as_uri="http://localhost:8080", realm="http://localhost:8080/", ...

curl -s http://localhost:8080/.well-known/lws-configuration     # RFC 8414 metadata
curl -s http://localhost:8080/.lws/token \
     -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     --data-urlencode resource=http://localhost:8080/ \
     --data-urlencode subject_token="$CREDENTIAL" \
     -d subject_token_type=urn:ietf:params:oauth:token-type:jwt
#   {"access_token":"eyJ...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
#    "token_type":"Bearer","expires_in":300}
```

The token endpoint validates the `subject_token` with the suite its `subject_token_type` names
(`…:id_token` OpenID, `…:jwt` self-signed CID, `…:saml2` SAML) — its audience must name this
authorization server or its token endpoint — and issues an RFC 9068 JWT (`typ: at+jwt`, `ES256`, key
at `/.lws/jwks`) with `iss` this server, `sub` and `client_id` the credential's subject and client,
`aud` exactly the storage URI, and a lifetime of `lws.oauth.access-token-lifetime-seconds` (300 s)
that never outlives the credential. Only this storage is a valid `resource` (`invalid_target`
otherwise). A token request carrying a `DPoP` proof gets a DPoP-bound token (`cnf.jkt`,
`token_type: DPoP`). The storage validates an access token's signature (the issuer's `jwks_uri`, with
key rotation), issuer (the embedded server, or one in `lws.oauth.trusted-issuers`, whose metadata is
read from its `/.well-known/lws-configuration`), audience (exactly one value, this storage), and
`exp`/`nbf`/`iat`, and requires `sub`, `client_id` and `jti`.

**Credentials presented directly** — this server's behaviour before the baseline, and an additional
mechanism lws10-core permits — are still accepted unless
`lws.oauth.accept-authentication-credentials=false`. A single orchestrator routes each credential to
the right suite by shape and returns the authenticated principal, which is carried on the request and
read by the authorization layer:

| Suite | Credential | Verification key comes from |
|---|---|---|
| **OpenID Connect** | signed JWT (`iss` ≠ `sub`) | the issuer's JWKS, via OIDC discovery — trusted because the subject's controlled-identifier document (JSON, as the suite's example writes it, or RDF) links *the subject itself* to an `lws:OpenIdProvider` service whose `serviceEndpoint` equals `iss` (a provider named elsewhere in the document does not count) |
| **SSI Controlled Identifier** | self-issued JWT (`sub`=`iss`=`client_id`; an HTTPS URL, a `did:key` or a `did:web`) with `exp`, `iat` and a `kid` | the verification method the `kid` names among those the subject document's **`authentication`** relationship lists (CID 1.0 §3.3): controlled by the subject, a `JsonWebKey` or `Multikey`, not revoked or expired. A `did:key` expands to its DID document locally; a `did:web` is fetched from its `https://…/did.json` |
| **did:key** (discontinued) | self-issued JWT whose `did:key` subject names no `kid` | the key the identifier encodes — kept, deprecated, for credentials minted before the SSI-CID suite subsumed this one |
| **SAML 2.0** | signed SAML assertion (optionally base64) | a pre-configured trusted IdP key (out-of-band trust); the XML signature is validated, **bound to the assertion whose claims are read**, and `NameID`/`Issuer`/`Recipient` mapped to subject/issuer/client |

All JWT suites reject `alg: none` and enforce `exp`. SAML trust is configured via
`lws.saml.idp-certificates` (and optionally `lws.saml.trusted-issuers` / `lws.saml.audience`);
without a configured certificate the SAML suite is inactive. The SAML credential is deliberately
profiled tight against signature wrapping: the document must carry exactly one `saml:Assertion` and
exactly one `ds:Signature`, the signature must be that assertion's own enveloped signature naming it
by `ID`, and every claim is read from that assertion's direct children — so an assertion nested in a
`saml:Advice`, a signature over the enclosing `samlp:Response`, and a whole-document
(`Reference URI=""`) signature are all refused. Setting `lws.saml.audience` makes an
`AudienceRestriction` required, and every restriction present must name this storage. `jakartaee-pac4j` additionally
provides optional interactive OIDC sign-in for the Wicket UI when an OIDC client is configured.

**Proof-of-possession (DPoP, RFC 9449).** Use `Authorization: DPoP <access-token>` together with a
`DPoP: <proof-jwt>` header. The server verifies the proof (its `typ`, signature via the embedded
`jwk`, `htm`/`htu`, `iat` freshness, a `jti`, and `ath` over the access token) and requires the
access token's `cnf.jkt` to equal the proof key's JWK thumbprint — so a stolen token is useless
without the holder's private key. The `jti` is *consumed* (making the proof single-use) only after
the access token has itself validated and been found bound to the proof key: every check before that
point is a pure function of strings the caller supplies, so consuming earlier let an unauthenticated
client fill the replay cache one entry per request (finding M6).

A DPoP-bound access token (one carrying `cnf.jkt`) is **refused** when it is presented as
`Authorization: Bearer`, as RFC 9449 §7.1 requires: honouring it there would let anyone who
captured the token use it without the key, which is precisely what the binding exists to prevent.
Set `lws.dpop.require=true` to refuse plain `Bearer` outright.

**Audience binding.** Every JWT credential is checked against `lws.audience`, which defaults to
this storage's own IRI. A token whose `aud` names something else is always refused, and — unless
`lws.audience.require=false` — a token with no `aud` at all is refused too. This is what stops a
credential presented here being replayed against another LWS storage, and stops an OpenID ID token
minted for a different relying party of the same provider from authenticating as its subject here.
Self-signed credentials (SSI-CID, did:key) are additionally capped at `lws.token.max-lifetime-seconds`,
since their holder chooses their own expiry. Mint tokens accordingly — `DidKeyTool --audience <storage>`,
which now names the verification method (`<did>#<multibase>`) as `kid`, so its credentials are
self-signed CID credentials and can be exchanged at the token endpoint too.

### Authorization (Web Access Control)

Set `lws.access-control=wac` for multi-user authorization via
[Web Access Control](https://solidproject.org/TR/wac). Each resource may have an ACL resource
(`<resource>.acl`, or `<container>/.acl`), discoverable via the `Link: rel="acl"` header — that is
the address it is read and written at; the graph itself is kept in the server-internal
`urn:x-lws:acl:` namespace, so no resource a client creates can ever be its own governing ACL. ACLs
are RDF documents containing `acl:Authorization` rules:

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
# Bob may read & write everything under /shared/
<#bob> a acl:Authorization ;
    acl:accessTo <http://localhost:8080/shared/> ;
    acl:default  <http://localhost:8080/shared/> ;   # inherited by contained resources
    acl:agent    <https://bob.example/profile#me> ;
    acl:mode     acl:Read, acl:Write .
# Any signed-in agent may read it; the public may not
<#members> a acl:Authorization ;
    acl:accessTo <http://localhost:8080/shared/> ;
    acl:agentClass acl:AuthenticatedAgent ;
    acl:mode acl:Read .
```

Rules:

- **Modes** map to operations: `acl:Read`→GET/HEAD; `acl:Append`→POST/PUT-create; `acl:Write`→
  PUT-overwrite/PATCH/DELETE (Write implies Append); `acl:Control`→read/write the resource's ACL.
- **Agents**: `acl:agent <webid>`; `acl:agentClass foaf:Agent` (everyone, incl. anonymous) or
  `acl:AuthenticatedAgent` (any signed-in agent); or `acl:agentGroup <group>` — membership is
  resolved by dereferencing the group document (from the local store, or over HTTP for an external
  group) and checking `vcard:hasMember`, cached for `lws.wac.group-cache-seconds`. An external
  group document is dereferenced *before* the storage transaction that needs the decision opens,
  never inside it: the metadata store admits one writer, and the group address comes out of the
  requester's own ACL, so a slow host would otherwise stall every write in the storage. A group
  that cannot be resolved simply does not match (its authorization is skipped; the others still
  apply), is not remembered as an empty group, and is not retried for
  `lws.wac.group-failure-cache-seconds`. One decision dereferences at most
  `lws.wac.max-group-fetches-per-decision` documents.
- **Resolution**: a resource's own ACL (`acl:accessTo`) wins; otherwise the nearest ancestor
  container's ACL applies through `acl:default` (inheritance), up to the root. The nearest ACL
  fully overrides ancestors — there is no super-owner, so include yourself when delegating a subtree.
- **Bootstrap**: the root ACL is created at startup from `lws.owners` (Read/Write/Control + public
  Read if `lws.public-read`); with no owners — which requires `lws.dev.open=true` — the root is
  opened to the public instead. That development ACL is marked as such and is **rebuilt** from
  `lws.owners` the first time the server starts with owners configured, because otherwise the
  lockdown would do nothing: it used to be written once and never revisited. A root ACL you wrote
  yourself carries no marker and is never rebuilt (it is warned about if it grants everyone
  `acl:Control`).
- Editing an ACL requires `acl:Control` on its target (ACLs are not themselves access-controlled,
  avoiding infinite regress).

To create users, point each at their OIDC issuer (their WebID document must link that WebID — the
exact IRI the token's `sub` carries — to an `lws:OpenIdProvider` service for that issuer; see
Authentication) and grant their WebID the modes they need in the relevant ACLs. The interactive
console login applies the same check as the API.

### Notifications

Discover support in the storage description (a `NotificationService` with a `serviceEndpoint` and
`subscriptionType: ["WebhookSubscription"]`). Create a subscription with an authenticated
`application/lws+json` POST to `/.lws/subscriptions`:

```json
{ "@context": ["https://www.w3.org/ns/lws/v1"],
  "type": "WebhookSubscription",
  "topic": ["http://localhost:8080/some/container/"],
  "inbox": "https://example.org/inbox",
  "expires": "2026-12-31T00:00:00Z" }
```

The answer is `201` with the subscription's `Location` and an `application/lws+json` body carrying
`type`, `subscription` (its URL) and the `expires` the server applied. `GET` on the endpoint lists the
caller's subscriptions as an LWS container; `GET` on a subscription returns its state and `DELETE`
cancels it. RDF is still available by asking for it.

Container topics are recursive. The server enforces that the subscriber may read every topic, and
will not deliver a notification for a resource the subscriber cannot read — including on **delete**,
where the decision is captured *before* the resource is removed. A container's subscriber therefore
learns nothing about a private child that was deleted from it: not that it existed, not its IRI, not
who removed it. That decision is also made with **no request context**: notification fan-out runs on
the thread of whoever made the change, so the writer's `Origin` and `LWS-Purpose` are set aside
first — a subscriber is not the app that happened to trigger the change, and an `acl:origin` rule
scoped to that app does not apply to a webhook. On each change it POSTs an `application/lws+json`
notification in the lws10-core data model to the inbox:

```json
{ "@context": ["https://www.w3.org/ns/lws/v1", "https://www.w3.org/ns/activitystreams"],
  "type": "Notification",
  "storage": "http://localhost:8080/",
  "activity": { "id": "urn:uuid:…", "type": ["Create"],
                "object": { "id": "http://localhost:8080/some/container/new", "type": ["DataResource"] },
                "target": "http://localhost:8080/some/container/",
                "published": "2026-09-22T10:30:00.000Z" } }
```

`target` names the container a `Create` added to and `origin` the one a `Delete` removed from; the
`actor` is omitted unless `lws.notifications.include-actor=true`, as the core's privacy
considerations advise. Each delivery is signed with RFC 9421 HTTP Message Signatures (covering
`@method @scheme @authority @path content-type content-digest`, with `created` + `keyid`). The
`keyid` is the id of the signing key's verification method in the storage description —
`<storage URI>#<thumbprint>` — so a receiver strips the fragment, dereferences the storage URI and
finds the key there, as lws10-notifications-webhook specifies; it is also still in `/.lws/jwks`.
Subscriptions may declare an `expires` instant; a background task purges expired subscriptions on the
`lws.subscription.purge-interval-seconds` schedule.

Because the `inbox` is chosen by the client, delivery is guarded like any other outbound fetch:
`lws.webhook.*` refuses inboxes resolving to loopback, private, link-local or metadata addresses,
checked both when the subscription is created (a `400`) and before every delivery attempt. Point a
subscription at an internal consumer by allow-listing its host. Subscription creation requires an
authenticated subscriber (`lws.subscriptions.allow-anonymous`), is capped per subscriber
(`lws.subscriptions.max-per-subscriber`) and is given a bounded lifetime
(`lws.subscriptions.max-lifetime-seconds`) so open-ended subscriptions cannot accumulate. The
request body must declare a JSON media type (`415` otherwise) and may name at most 64 topics, both
checked before anything is spent on it, since anonymous creation is a supported configuration.
Delivery failure counts are kept server-side and are not exposed in the subscription's
representation. Listing the subscription collection requires authentication and returns only the
caller's own subscriptions, or all of them for a storage controller.

Delivery outcomes are classified rather than retried blindly: `5xx`, `429` and transient I/O are
retried up to `lws.webhook.max-attempts`; a `410 Gone` deactivates the subscription immediately; any
other `4xx`, and an inbox this client cannot even make a request to (a non-HTTP scheme), is counted
as a failure and not retried, because nothing about the next attempt would differ. The pool is
bounded in three directions — worker count, queue depth and per-host in-flight deliveries — and
back-off is scheduled rather than slept, so one unresponsive subscriber cannot hold a worker or grow
the queue without limit. Work refused by a bound is dropped with a warning and counted as a failed
delivery.

### Search & Type Index

The storage description advertises a `TypeIndexService` and a `TypeSearchService`, each with a
`serviceEndpoint`. Both answer `application/lws+json`, are paginated (`?page=N` with `first`/`prev`/
`next`/`last` `Link` relations) and are **authorization-filtered for the requesting client** — a
type or resource the client cannot read never appears, and `totalItems` counts only that view, so a
client cannot discover that a private type or resource exists. Responses are `Cache-Control:
private, no-store`.

A resource's types are its structural LWS type (`lws:Container` / `lws:DataResource`), the types a
client declared with `Link: rel="type"` on a write (lws10-index's preferred source), and any
`rdf:type` its own representation asserts about itself (the resource IRI or a hash fragment of it).

- **Type index** — `GET /.lws/type-index` lists the distinct types visible to the client:
  ```json
  { "@context": "https://www.w3.org/ns/lws/v1", "type": "TypeIndex", "totalItems": 5,
    "items": [ { "id": "https://schema.org/Person" }, { "id": "https://schema.org/Event" } ] }
  ```
- **Type search** — an HTTP `QUERY` (RFC 10008) whose body is an `application/lws-query+json`
  filter, returning a synthetic `ContainerPage`. A nested array is OR and the outer array is AND:
  ```json
  QUERY /.lws/type-search   Content-Type: application/lws-query+json
  { "type": [ ["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"],
              "https://www.w3.org/ns/lws#DataResource" ] }
  ```
  selects `(schema:Person OR foaf:Person) AND lws:DataResource`. The filter is plain JSON — an
  `@`-member is ignored — and every key is optional: `{}` matches every resource the client may read.
  Besides `type`, a key names a link relation, with the same grammar: a **registered name** such as
  `describedby` matches the links the resource's metadata declares, and a **URI** matches those and
  the triples its representation asserts with that predicate. A relation the server does not index
  yields no matches, indistinguishably from a target nothing declares; the server-managed relations
  are never indexed. `OPTIONS` answers `Allow: OPTIONS, QUERY` and `Accept-Query:
  application/lws-query+json`. Page links are opaque and dereferenced with `GET` (they carry the
  filter, not the authorization). Errors follow lws10-index: `400` for a missing `Content-Type`, a
  malformed filter, an empty OR-group or a value that is not an absolute IRI; `415` (with
  `Accept-Query`) for another query format; `422` for a filter past the complexity bound — never
  silently narrowed —; `406` for an `Accept` that excludes JSON; `404` for a page link that is past
  the last or no longer recognized. The `GET`/`POST` search forms of the drafts before July 2026 are
  gone.

### Access Requests & Grants

The storage description advertises an `AccessRequestService` and an `AccessGrantService` (each with a
`serviceEndpoint` and the `conformsTo` access profile). Both are LWS containers served as
`application/lws+json` — their listings are container representations, paginated like any other,
whose members are data resources typed `["DataResource", "AccessGrant"]` (or `AccessRequest`) with
`format` `application/lws+json`:

- **Request** — any authenticated agent `POST`s an `AccessRequest` to `/.lws/access-requests`
  (`201` + `Location`); the requester or a controller may `GET`/list/`DELETE` it.
- **Grant** — a storage controller `POST`s an `AccessGrant` to `/.lws/access-grants`; deleting it
  revokes the grant.

```json
POST /.lws/access-grants            Content-Type: application/lws+json   (storage controller)
{ "@context": "https://www.w3.org/ns/lws/v1", "type": ["AccessGrant"], "storage": "http://localhost:8080/",
  "access": [ { "type": ["AccessPolicy"], "action": ["read"], "assignee": "https://bob.example/me",
               "target": { "type": "StorageResource", "value": ["http://localhost:8080/doc"] } } ] }
```

A grant is **enforced** by a grant-aware authorizer layered over the base model (owner or WAC): the
operation is permitted if the base permits it *or* an active grant authorizes it, so the assignee
can act on the targets without any ACL edit, and deleting the grant withdraws the access
immediately. Actions map to operations (`read`→GET/HEAD, `modify`→PUT/PATCH, `create`→POST,
`delete`→DELETE); `assignee` may be `http://xmlns.com/foaf/0.1/Agent` for public access; a `target`
`value` matches a resource exactly or, for a container value, its subtree, and the target's matcher
`type` narrows that: `StorageResource` (the default) matches any resource, `DataResource` and
`Container` only their own kind, and any other matcher is refused at creation. Constraints are
evaluated fail-closed — `dateTime`, `client`, `format`, `type` and `purpose` are honoured (`format`
and `type` from the target's metadata, `type` including the types its `Link` headers declare;
`purpose` from a client-declared `LWS-Purpose` request header); `mediaType`, the `format` operand's
name before August 2026, is still honoured. Grants never confer `Control`. As lws10-core's privacy
considerations advise, a grant with a `client` constraint is not shown to its assignee through a
different client.

A grant carries only the authority of the agent who issued it, and that authority is **re-checked at
every evaluation** rather than trusted from issuance: remove an issuer from `lws.owners`, or revoke
its `acl:Control` in the root ACL, and every grant it ever made stops authorizing on the next
request, with no restart and no record to clean up. (So an owner rotation is also a grant
revocation — re-issue anything you meant to keep.) Issuance itself requires a configured controller,
so it is refused outright while `lws.owners` is empty. `storage` must name this storage and every
`target.value` must be inside it, checked at creation. The server logs the number of stored grants
at startup, and how many are inert because their issuer no longer controls the storage — a grant
appears in no owner list and no ACL, so that count is the only place an operator inheriting a
storage would see one. Audit them at `/.lws/access-grants`.

On creation the server delivers a signed notification (a `Create` activity about the new document,
its `object` typed `["DataResource", "AccessGrant"]` or `AccessRequest`, RFC 9421-signed like a
webhook) to the relevant inboxes: the document's own `inbox`, the configured controller inbox for a new request, and
— for a grant that references its request via a `request` link — the associated request's inbox.

### SPARQL endpoint (optional)

For administrative/analytical access, an embedded [Apache Jena Fuseki](https://jena.apache.org/documentation/fuseki2/)
SPARQL endpoint can be exposed over the live TDB2 dataset (`lws.sparql.endpoint.enabled=true`, local
`TDB2` backend only). It runs as its own lightweight server on `lws.sparql.endpoint.port`, sharing
the same dataset (so it sees committed data immediately):

```bash
curl --data-urlencode 'query=SELECT (COUNT(*) AS ?n) WHERE { GRAPH ?g { ?s ?p ?o } }' \
     -H 'Accept: application/sparql-results+json' http://localhost:3030/lws/sparql
```

When enabled it is advertised in the storage description as a service whose `type` is the W3C SPARQL
Service Description `Service` class (`http://www.w3.org/ns/sparql-service-description#Service`) and
whose `serviceEndpoint` is `lws.sparql.endpoint.public-url` (or a URL derived from the base host,
port and dataset) — so clients can discover it via discovery like any other LWS service.

> **Security:** this endpoint operates on the whole dataset, so it **bypasses WAC/owner
> authorization** and exposes the internal administrative graphs (resource registry, ACLs,
> subscriptions, access grants, linkset metadata). It is **disabled by default**, and when enabled is
> **query-only** (`read-only`) and bound to **loopback** unless reconfigured. Treat it as a trusted
> endpoint — keep it loopback-only or behind a trusted reverse proxy.

## Management UI

An Apache Wicket console is mounted at `/app/` (home `/app/browse`): browse the hierarchy and —
when signed in with sufficient permission — create resources (typing RDF/text or uploading a
binary file), edit RDF, replace a binary resource's bytes by upload, delete resources, and edit
each resource's WAC ACL. Actions run in-process as the signed-in principal, so authorization is
enforced exactly as for the HTTP API, and the UI only offers actions the current principal is
allowed to perform.

Sign in at `/app/login` by: pasting an OpenID Connect **ID token** (validated just like the HTTP
API); **OpenID Connect single sign-on** (browser redirect via pac4j, shown when an OIDC client is
configured); or, when `lws.ui.dev-login=true`, a **developer sign-in** that lets you act as any
WebID (impersonation — development/administration only).

**Cross-site request forgery.** Wicket has no CSRF token and its stateful callback URLs are
guessable, so the console registers Wicket's `ResourceIsolationRequestCycleListener` (Fetch
Metadata with an Origin fallback — *not* on by default) and every destructive action is a POST
rather than an `<a href>` GET. A GET-triggered delete is reachable from any other site, and from
link prefetchers and mail/chat scanners, without the user doing anything. The session cookie is
`HttpOnly` and `SameSite=Strict` in both bootstraps, and `Secure` when the server itself serves
HTTPS.

## Tested

`mvn package` plus a live smoke test of every operation against both the Spring Boot jar and the
bare-Jetty launcher: container/description/JWKS reads, RDF create/read in Turtle and JSON-LD,
container PUT, PATCH round-trip, binary upload/download, subscriptions, OPTIONS, conditional
requests, and the delete guards (root → 403, non-empty container → 409).

Web Access Control is covered by JUnit tests
([`WacAclServiceTest`](src/test/java/com/ebremer/lws/server/auth/WacAclServiceTest.java): owner
control, public vs authenticated access, per-agent grants, `acl:agentGroup` membership,
`acl:origin` restriction, container inheritance, nearest-ACL override) and a live ACL loop (create
an ACL, see access revoked, confirm
control-lockout). The
management UI is covered by [`LwsUiTest`](src/test/java/com/ebremer/lws/server/ui/LwsUiTest.java)
(WicketTester): capability gating (anonymous / owner / non-owner), creating a resource through the
form, and ACL editing. The authentication suites are covered by JUnit tests
(`DidKeyValidatorTest`, `SsiCidValidatorTest`, `DidsAndMultikeyTest`, `SamlValidatorTest`,
`LwsCredentialValidatorTest`): valid Ed25519/P-256/RSA credentials are accepted and forged, expired,
mismatched, untrusted-key and untrusted-issuer credentials are rejected; the self-signed CID suite's
CID 1.0 retrieval rules (only `authentication` methods, controller, revoked/expires, no published
private key, `JsonWebKey` and `Multikey`) and its `did:key` and `did:web` subjects are each pinned.
The authorization framework is covered end to end by
[`LwsAuthorizationTest`](src/test/java/com/ebremer/lws/server/LwsAuthorizationTest.java): the
metadata, a token exchange and every token-endpoint refusal, each access-token check against a stub
external authorization server, a storage that accepts access tokens only, and DPoP-bound tokens. The OpenID Connect suite is covered by
[`LwsOpenIdValidatorTest`](src/test/java/com/ebremer/lws/server/auth/LwsOpenIdValidatorTest.java)
against an in-process [`MockOidcProvider`](src/test/java/com/ebremer/lws/server/auth/MockOidcProvider.java)
(discovery + JWKS + controlled-identifier doc, minting RS256 ID tokens): a valid token from a
trusting subject is accepted, while untrusted-subject, expired and forged-signature tokens are
rejected; and [`OidcSsoRedirectTest`](src/test/java/com/ebremer/lws/server/OidcSsoRedirectTest.java)
boots the server and asserts `GET /app/oidc-login` redirects (302) to the provider's authorization
endpoint. DPoP is covered by `DpopValidatorTest` (proof verification + nonce gating) and
`DpopNonceServiceTest` (the stateless HMAC nonce), subscription purging by `SubscriptionPurgeTest`,
and the `did:key` owner-token helper by
[`DidKeyToolTest`](src/test/java/com/ebremer/lws/server/tools/DidKeyToolTest.java) (the minted token
is accepted by the validator and the seed re-mints the same DID).

Webhook delivery is covered end-to-end by
[`WebhookDeliveryTest`](src/test/java/com/ebremer/lws/server/WebhookDeliveryTest.java): it boots the
server plus a real HTTP inbox, subscribes, makes a change, and asserts the inbox receives a signed
notification in the lws10-core data model whose RFC 9421 HTTP Message Signature and RFC 9530
Content-Digest verify against the key it finds by following the receiver's steps in
lws10-notifications-webhook — strip the `keyid`'s fragment, dereference the storage, look the
verification method up — exactly what a real subscriber would check.

The Type Index / Type Search services are covered by
[`SearchIndexTest`](src/test/java/com/ebremer/lws/server/SearchIndexTest.java) (service discovery,
the type index, `QUERY` search with single/OR/AND/native-container/relation filters and the filter
grammar's edge cases, page links, and the `400`/`404`/`405`/`406`/`415`/`422` error responses) and
[`SearchIndexAuthzTest`](src/test/java/com/ebremer/lws/server/SearchIndexAuthzTest.java), which runs
in owner mode with a `did:key` owner and asserts the security guarantees: an owner sees private
types and resources while an anonymous client sees neither (cannot even learn they exist), plus the
pagination `Link` relations and the out-of-range-page `404`.

Access Requests & Grants are covered by
[`AccessGrantsTest`](src/test/java/com/ebremer/lws/server/AccessGrantsTest.java): a controller's
grant lets another `did:key` agent read a resource it otherwise cannot (scoped to the granted
action), revoking the grant withdraws the access, a public (`foaf:Agent`) grant admits an anonymous
reader, `format` (and the former `mediaType`) and `purpose` constraints that gate the grant (by the
target's media type and the client-declared `LWS-Purpose`), target matcher types, the container
listing, client-bound grants hidden from other clients, plus the request lifecycle, controller-only
grant issuance, discovery advertisement, and the `401`/`403`/`415` cases.
[`AccessNotificationTest`](src/test/java/com/ebremer/lws/server/AccessNotificationTest.java) asserts
the signed notification is delivered (with a matching Content-Digest) to the document's own
`inbox`, to the configured controller inbox for a new request, and to a linked request's inbox for a
grant that references it.

End-to-end, [`EndToEndTest`](src/test/java/com/ebremer/lws/server/EndToEndTest.java) boots the real
bare-Jetty stack (`JettyLauncher.buildHandler` over a live `LwsComponents`) on a free port and
drives it with an HTTP client: storage root / description / JWKS reads with Link headers and
content negotiation, RDF create→read (Turtle & JSON-LD)→replace→delete, container PUT + PATCH +
empty/non-empty delete guards, binary upload/download round-trip, conditional requests, OPTIONS,
error codes (404/403/401), JSON Merge Patch on a JSON resource, the subscription lifecycle, and the
management UI. The RFC 7386 algorithm itself is covered by
[`JsonMergePatchTest`](src/test/java/com/ebremer/lws/server/core/JsonMergePatchTest.java) against the
spec's Appendix A examples.

The embedded SPARQL endpoint is covered by
[`FusekiSparqlEndpointTest`](src/test/java/com/ebremer/lws/server/FusekiSparqlEndpointTest.java): a
query returns the live data the server has committed, and a SPARQL Update is refused while the
endpoint is read-only.

The lws10-core operations and processes are covered by
[`OperationsConformanceTest`](src/test/java/com/ebremer/lws/server/OperationsConformanceTest.java):
the `application/lws+json` container representation and its content negotiation (with the requested
`Content-Type` echoed), byte-range requests (`206`/`416`), conditional replacement (`428`/`412`/
`204`), `If-Modified-Since` (`304`), recursive `Depth: infinity` container delete, the
`rel="up"`/`rel="linkset"` metadata links, the linkset resource (read, OPTIONS,
conditional Merge-Patch/PUT), linkset removal on delete (including that a re-created path does not
inherit the old linkset), the storage description as
`application/lws+json` (advertising its own `StorageDescription` service), and
`application/problem+json` errors, and the SPARQL Update `LOAD`/`SERVICE` SSRF guard (also unit-tested
by [`SparqlUpdateGuardTest`](src/test/java/com/ebremer/lws/server/core/SparqlUpdateGuardTest.java)).
The storage quota (`507`) is covered by
[`QuotaTest`](src/test/java/com/ebremer/lws/server/QuotaTest.java). Container-listing pagination — page slicing, `first`/`prev`/
`next`/`last` Link relations, per-page ETags, and the out-of-range `404` — is covered by
[`ContainerPaginationTest`](src/test/java/com/ebremer/lws/server/ContainerPaginationTest.java), and
per-member authorization filtering of listings by
[`ResourceServiceListingTest`](src/test/java/com/ebremer/lws/server/core/ResourceServiceListingTest.java)
(a member the client cannot read is omitted, and the listing is client-specific).

## Known limitations

The notable limitations and deliberate design choices are summarised below.

- Tracks the LWS **editor's drafts** — currently those of 21 September 2026 (`w3c/lws-protocol` @
  `3ddc642`); gaps are filled with LDP/Solid conventions and may change. [COMPLIANCE.md](COMPLIANCE.md)
  lists the deliberate departures.
- The **storage URI is the root container's URI**, as lws10-core permits, so `/` has two
  representations chosen by `Accept`: the storage description by default, the root listing for a
  container type. A client that fetched `/` with no `Accept` and expected the listing now gets the
  description; asking for `application/lws+json` (or RDF) gets the listing, as it always did.
- Container listings are filtered per member by read authorization (`items` and `totalItems`
  reflect only the resources the client may read), so a listing is client-specific. The linkset
  resource stores its user-managed links as a JSON document and merges server-managed links on read.
- Authorization offers two modes via `lws.access-control`: single-tenant **owner/public-read**, or
  multi-user **Web Access Control** (WAC). Both sit behind a pluggable
  [`Authorizer`](src/main/java/com/ebremer/lws/server/core/Authorizer.java) (the LWS core draft
  leaves authorization unspecified, so WAC follows the Solid conventions). WAC supports
  `acl:agent`, `acl:agentClass`, `acl:agentGroup`, and `acl:origin` (browser/app-scoped access via
  the request's `Origin`). A browser application needs **both** halves: its origin in
  `lws.cors.allowed-origins`, so the browser lets it read the response at all, and — if the ACL
  restricts by `acl:origin` — a matching `acl:origin`. They are independent by design: one is what
  the browser is told, the other is what the server authorizes.
- **Cross-origin access is off until configured.** `lws.cors.allowed-origins` is empty by default and
  no `Access-Control-*` header is sent; since an `Authorization` header makes every authenticated
  request non-simple, a browser application on another origin cannot reach the API until an origin is
  listed. `Access-Control-Allow-Credentials` is **never** sent — the API authenticates with a token
  the script supplies, never with an ambient cookie — so an allowed origin can only reach the storage
  with a token it already holds, and the console's session cookie cannot be borrowed; `/app` and
  `/callback` are excluded from CORS outright as well. A preflight is answered by the CORS filter
  itself, ahead of authentication, with a fixed method and header set rather than one derived from
  the target, so it discloses nothing about what is stored. `*` is accepted (legal precisely because
  credentials are never sent) but **refused at startup in open mode**, where every request is
  authorized anonymously and `*` would hand the whole storage to any site a browser visits.
- PATCH supports `application/merge-patch+json` (RFC 7386 — the LWS-required format) and
  `application/sparql-update`. **Merge Patch applies to JSON (non-RDF) resources and to linksets, and
  is refused on RDF resources with `415`**; use SPARQL Update to edit a graph. It used to be offered
  on RDF via the JSON-LD representation, and that was not a translation the patch survived: Jena
  emits a flat node object only for a single-subject model, and for two or more it emits
  `{"@graph":[…]}`, so merging the client's members at the top level turned the document into a
  *named graph* node and the re-parse kept only the patch — a three-triple resource measured back as
  one triple on a fresh blank node, answered `204`. Two subjects is the ordinary shape (a resource
  plus its own `#it` fragment). **JSON Patch** (RFC 6902, `application/json-patch+json`) is likewise
  accepted for JSON (non-RDF) and linkset resources (a failed `test` operation or an unresolvable
  JSON Pointer yields `409`) and not for RDF resources, whose JSON-LD shape is not a stable pointer
  target — the same reason, now applied consistently to both dialects. SPARQL Update is
  correspondingly strict about staying in the resource's own graph (see above). SPARQL Update `LOAD`/`SERVICE` (which
  would make the server fetch a URL — an SSRF vector) are blocked unless their host is in
  `lws.sparql-update.allowed-hosts`. N3 Patch (`text/n3`) is intentionally not implemented — the LWS
  Editor's Draft does not require it (JSON Merge Patch is the only PATCH format a server must support).
  Refusing merge patch on RDF resources is a deliberate departure from lws10-core's "MUST minimally
  support JSON Merge Patch", recorded in [COMPLIANCE.md](COMPLIANCE.md).
- DPoP is enforced for the `DPoP` scheme (RFC 9449: proof signature, `htm`/`htu`, `iat` freshness,
  `jti` replay, `ath`, and `cnf.jkt` binding), with optional server-issued nonces (§8) via
  `lws.dpop.require-nonce` — a nonceless request is answered `401` + `DPoP-Nonce`. The `jti` replay
  cache (a bounded, TTL-evicting [Caffeine](https://github.com/ben-manes/caffeine) cache, as are the
  OIDC trust/JWKS, SSI-CID subject-document and WAC agentGroup caches) and the (stateless HMAC) nonce
  secret are per-process; a shared cache/secret would be needed across a cluster. Entries live for
  the whole `iat` acceptance window rather than part of it, and the cache is sized by
  `lws.dpop.jti-cache-size`: an entry evicted because the cache is **full** has not expired, so the
  proof that wrote it is replayable again, and the server warns when that starts happening.
- **Outbound-fetch SSRF guard.** Authentication dereferences URLs from untrusted token claims (the
  WebID/CID `sub`, the OIDC issuer `iss` and its JWKS) and WAC dereferences `acl:agentGroup`
  documents. These are gated by an `OutboundFetchPolicy`: non-`http(s)` schemes are always refused
  (closing `file://` local-file reads via Jena's loader), and by default hosts resolving to loopback,
  private, link-local (incl. the cloud-metadata `169.254.169.254`), wildcard or multicast addresses
  are blocked (`lws.fetch.block-private-addresses`, with a `lws.fetch.allowed-hosts` exemption for an
  internal IdP). `HttpDocumentLoader` caps document size (2 MiB), bounds the whole
  exchange at 20 s across every hop, and follows redirects itself (the client is built with
  `Redirect.NEVER`) so that the policy is re-applied to each of at most five hops rather than only
  to the URL first presented.
- **Request bodies are bounded before they are trusted.** `lws.max-request-bytes` (64 MiB default) is
  enforced from `Content-Length` and again while reading a chunked body, and every JSON body is
  refused with `400` if nested deeper than 64 levels — checked in one non-recursive scan *before* the
  parser sees it, because `jakarta.json` parses recursively and a 24 KB body of `[[[[…` would
  otherwise throw `StackOverflowError` inside it, aborting the response with no `problem+json` at
  all. Endpoints that read a body before authorizing anything also require a JSON media type up
  front.
- The storage **quota** (`lws.quota.max-bytes`) counts binary (non-RDF) content bytes only; RDF
  graph storage is not metered. A write over the limit is refused with `507`.
- **Digest fields** (RFC 9530) are supported for `sha-256`/`sha-512`: an inbound `Content-Digest` is
  verified against the request body before any write, and `Want-Repr-Digest`/`Want-Content-Digest` on
  a read are answered with the corresponding `Repr-Digest`/`Content-Digest`. Non-RDF resources persist
  their content SHA-256 so the digest is served without re-reading the blob. Only the two
  RFC-recommended algorithms are offered; the obsolete `md5`/`sha`/`unixsum`/`crc32c` algorithms are
  neither produced nor verified (an unsupported inbound algorithm is ignored rather than rejected).
  Support is advertised both in-band (`Want-Content-Digest` on `OPTIONS`/write responses) and as a
  capability in the storage description.
- Access **grants** are enforced for their `action`/`assignee`/`target` (value and matcher type) and
  all constraint types (`dateTime`/`client`/`format`/`type`/`purpose`). `acl:origin` and the `purpose` (`LWS-Purpose`
  header) are **client-declared**, not cryptographically attested — as is the nature of
  origin/purpose policy.
- The Type Index / Type Search services serve resource **types** from an in-memory derived index,
  built lazily on first use and maintained incrementally from resource events (create/update/delete);
  relation targets are not cached and are queried on demand for the relations a search needs. Per
  lws10-index, type/relation membership may be eventually consistent — though synchronous event
  delivery makes it read-your-writes in practice. **Authorization is never cached**: it is applied
  live, per request, over the index, so a revoked grant takes effect immediately, and `totalItems`
  counts only the requesting client's authorized view. Descriptive relations are the links a
  resource's metadata declares (registered names and URIs) and, for a URI, the predicate in its own
  representation; structural/protocol relations are never indexed. Only the baseline
  `application/lws-query+json` format is accepted; no alternate query format is offered.
- The **authorization server** is deliberately minimal: token exchange only (no authorization-code
  flow, no refresh tokens, no client registration — lws10-core identifies a client by the URI in its
  credential), public clients, one signing key (`keys/oauth-es256.jwk`; delete it and restart to
  rotate, which invalidates outstanding tokens at most `lws.oauth.access-token-lifetime-seconds`
  early), and tokens for this storage only. An external authorization server must publish RFC 8414
  metadata at `/.well-known/lws-configuration` and issue RFC 9068 (`typ: at+jwt`) tokens.
- `buji-pac4j` is intentionally **not** used: its current release pulls the `javax`-servlet pac4j
  module, which is incompatible with this Jakarta (Servlet 6 / Jetty 12) stack. The pac4j filters are
  registered directly instead.
- **Apache Shiro is not used.** It was, briefly, and nothing ever read the `Subject` it built: there
  is no `SecurityUtils.getSubject()`, `hasRole` or `isPermitted` anywhere in the server, because
  authorization is decided by `core.Authorizer` from the resource IRI and the required access mode.
  The per-request `login()` it needed created a 30-minute in-memory session every time and nothing
  ever logged out, so — `did:key` credentials being self-issued and free to mint offline — anyone
  could pin hundreds of thousands of session objects in the heap without a single request having to
  succeed (finding H20). No LWS code references it now; it reaches the classpath only as a dependency
  of `jena-fuseki-main`, which is declared `<optional>` so that a *downstream consumer* of this
  artifact does not inherit it. `<optional>` does not shrink **this** build: the packaged
  `lws-server.jar` still contains Fuseki and Shiro, and the embedded SPARQL endpoint is switched off
  by configuration (`lws.sparql.endpoint.enabled`), not by absence. Removing them from the jar means
  dropping the `jena-fuseki-main` dependency.

## License

Copyright 2026 Erich Bremer.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
compliance with the License. You may obtain a copy of the License at
<https://www.apache.org/licenses/LICENSE-2.0>.

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the [`LICENSE`](LICENSE) file for the specific language governing permissions and
limitations under the License, and [`NOTICE`](NOTICE) for attribution.

Third-party dependencies are declared in `pom.xml` and are distributed under their own licenses.
