# LWS Server

A [Linked Web Storage](https://w3c.github.io/lws-protocol/) server implementing the W3C LWS
Protocol, written as plain Jakarta servlets and bootstrapped (for now) by Spring Boot on an
embedded Eclipse Jetty container.

It implements:

- **[LWS Core](https://w3c.github.io/lws-protocol/lws10-core/)** — the resource/containment model and CRUD operations.
- **[LWS Vocabulary](https://w3c.github.io/lws-protocol/lws10-vocab/)** — the `https://www.w3.org/ns/lws#` terms.
- **Authentication suites** — all four LWS suites:
  [OpenID Connect](https://w3c.github.io/lws-protocol/lws10-authn-openid/),
  [SAML 2.0](https://w3c.github.io/lws-protocol/lws10-authn-saml/),
  [Self-signed Controlled Identifier](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/), and
  [Self-signed did:key](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/).
- **[LWS Notifications](https://w3c.github.io/lws-protocol/lws10-notifications/)** — webhook subscriptions with RFC 9421 HTTP Message Signatures.
- **[LWS Search & Type Index](https://w3c.github.io/lws-protocol/lws10-searchindex/)** — the `TypeIndexService` and `TypeSearchService` discovery services (authorization-filtered).
- **[Access Requests & Grants](https://w3c.github.io/lws-protocol/lws10-core/#access-requests)** — ODRL-based `AccessRequestService`/`AccessGrantService`; grants are enforced and revocable.

> The LWS core **operations** (create/read/update/delete, container representation, metadata) are
> implemented from the normative `Operations/` source in the [spec repository](https://github.com/w3c/lws-protocol/tree/main/lws10-core/Operations),
> which is ahead of the rendered Editor's Draft. Where the draft is still silent this implementation
> follows the **LDP / Solid Protocol conventions** it derives from (trailing-slash containers,
> `Link: rel="type"` interaction models, content negotiation, conditional requests). Because the
> source is in flux, these details may change.

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
├─ rdf/                 RdfStore abstraction; Tdb2RdfStore + RemoteSparqlRdfStore; formats/IO
├─ storage/             BinaryStore abstraction + FileSystemBinaryStore (non-RDF bytes)
├─ core/                resource model, ResourceService (the protocol engine), registry,
│                       storage description, access policy, IRIs/etags
├─ auth/                LWS OpenID validator (Nimbus), Shiro realm/filter, pac4j UI login
├─ notifications/       subscriptions, webhook dispatch, RFC 9421 signatures, Ed25519 keys
├─ http/               the Jakarta servlets (resource, storage-description, subscriptions, jwks)
└─ ui/                  Apache Wicket storage browser
```

### Metadata store (pluggable SPARQL backend)

All RDF goes through [`RdfStore`](src/main/java/com/ebremer/lws/server/rdf/RdfStore.java), which
hands the service layer a Jena `RDFConnection`. Jena implements that connection identically over
a local TDB2 dataset and over any remote SPARQL 1.1 service (Query + Update + Graph Store
Protocol), so the backend is a one-line wiring choice:

- **TDB2** (default) — embedded, transactional, zero-ops.
- **Remote SPARQL** — point at Fuseki, GraphDB, Blazegraph, Neptune, … (see config below).

Resource content is stored as **one named graph per RDF resource**; non-RDF resources are stored
as opaque bytes by a [`BinaryStore`](src/main/java/com/ebremer/lws/server/storage/BinaryStore.java)
(filesystem by default), with their metadata in the RDF store. Administrative metadata
(type, containment, timestamps, etags, ACL, subscriptions) lives in dedicated named graphs.

## Build

```bash
mvn -DskipTests package
```

Requires JDK 21+ (built and tested on JDK 25). Produces an executable `target/lws-server.jar`.

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
| `lws.owners` | *(empty)* | Space/comma-separated owner WebIDs. **Empty ⇒ open dev mode** |
| `lws.public-read` | `true` | Default public-readability for new resources |
| `lws.access-control` | `OWNER` | `OWNER` (single-tenant) or `WAC` (multi-user Web Access Control) |
| `lws.sparql.mode` | `TDB2` | `TDB2` or `REMOTE` |
| `lws.sparql.query` / `.update` / `.gsp` | | Endpoints when `mode=REMOTE` |
| `lws.oidc.discovery-uri` / `.client-id` / `.client-secret` | | Enable interactive OIDC login for the UI |
| `lws.ui.dev-login` | `false` | Enable the UI's developer sign-in (impersonation; **dev only**) |
| `lws.saml.idp-certificates` | | PEM/DER X.509 cert paths of trusted SAML IdPs (enables the SAML suite) |
| `lws.saml.trusted-issuers` / `lws.saml.audience` | | Optional SAML issuer allow-list / expected audience |
| `lws.webhook.max-attempts` | `5` | Webhook delivery retries |
| `lws.subscription.purge-interval-seconds` | `3600` | How often expired subscriptions are purged (0 disables) |
| `lws.webhook.max-consecutive-failures` | `10` | Failures before a subscription is deactivated |
| `lws.search-index.enabled` | `true` | Advertise and serve the Type Index / Type Search services |
| `lws.search-index.page-size` | `100` | Max items per Type Index / Type Search response page |
| `lws.container.page-size` | `1000` | Max members per container-listing page (larger listings are paginated) |
| `lws.access-requests.enabled` | `true` | Advertise and serve the Access Request / Access Grant services |
| `lws.access-requests.controller-inbox` | | Inbox notified when a new access request is created |
| `lws.quota.max-bytes` | `0` | Max total binary-content bytes (`0` = unlimited); over-quota writes get `507` |
| `lws.dpop.require-nonce` | `false` | Require a server-issued nonce in DPoP proofs (RFC 9449 §8) |
| `lws.sparql-update.allowed-hosts` | | Hosts a SPARQL Update `LOAD`/`SERVICE` may fetch (empty = blocked) |
| `lws.fetch.block-private-addresses` | `true` | Block auth/WAC dereferences to private/loopback/metadata addresses (SSRF guard) |
| `lws.fetch.allowed-hosts` | | Hosts exempt from that block (e.g. an internal IdP) |
| `lws.sparql.endpoint.enabled` | `false` | Expose an embedded Fuseki SPARQL endpoint over the local dataset |
| `lws.sparql.endpoint.port` / `.dataset` / `.read-only` / `.loopback` | `3030` / `lws` / `true` / `true` | SPARQL endpoint port, dataset path, query-only, loopback-only |
| `lws.sparql.endpoint.public-url` | | Query URL advertised in the storage description (else derived from base host/port) |
| `lws.behind-proxy` | `false` | Trust `X-Forwarded-*` / `Forwarded` (RFC 7239) from a fronting TLS-terminating proxy |
| `lws.require-https` | `false` | Refuse to start unless `lws.base-uri` is `https://` (loopback exempt) |
| `lws.tls.enabled` | `false` | Terminate TLS in the server, provisioning a cert via ACME (bare-Jetty launcher) |
| `lws.tls.port` / `lws.tls.http-port` | `443` / `80` | HTTPS port, and the HTTP port serving the ACME challenge + redirect |
| `lws.tls.acme.directory-url` | Let's Encrypt prod | ACME directory (e.g. `…/acme-staging-v02…/directory` for testing) |
| `lws.tls.acme.domains` | base-URI host | Domain(s) to certify (space/comma separated) |
| `lws.tls.acme.email` | | Contact email for the ACME account |
| `lws.tls.acme.accept-terms-of-service` | `false` | MUST be `true` to register (agrees to the CA's ToS) |
| `lws.tls.acme.renew-before-days` / `lws.tls.dir` | `30` / `<data>/tls` | Renewal lead time; directory for the account key, domain key, and cert |

> **Security note:** with no `lws.owners` configured the server runs in **open mode** (all reads
> and writes permitted). Set owners to enforce the owner-based access policy.

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
owner. The self-signed [`did:key`](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/)
suite needs no identity provider, so a bundled helper can mint the very first owner offline:

```
# from the packaged fat jar
java -cp target/lws-server.jar -Dloader.main=com.ebremer.lws.server.tools.DidKeyTool \
     org.springframework.boot.loader.launch.PropertiesLauncher

# or, from a source checkout
mvn -q exec:java -Dexec.mainClass=com.ebremer.lws.server.tools.DidKeyTool
```

It prints (1) a `did:key:…` to drop into `lws.owners`, (2) a private-key seed to keep secret
(pass it back with `--key <seed>` to re-mint tokens for the same identity), and (3) a ready Bearer
token to send as `Authorization: Bearer <token>`. Options: `--ttl <seconds>` (token lifetime,
default 3600) and `--audience <aud>`. Put the DID in `lws.owners`, restart, and the token
authenticates you as that owner.

## HTTP API

| Method | Target | Behaviour |
|---|---|---|
| `GET`/`HEAD` | data resource | Content-negotiated representation (Turtle, JSON-LD, N-Triples, RDF/XML); binary streamed as-is, with byte-range support (`206`/`416`, `Accept-Ranges: bytes`) |
| `GET`/`HEAD` | container | `application/lws+json` listing (`id`/`type`/`totalItems`/`items[]` with `id`/`type`/`mediaType`/`size`/`modified`); content-negotiable as `application/ld+json`/`application/json` (the requested `Content-Type` is echoed) or RDF; paginated (`?page=N`, `Link` rel=`first`/`prev`/`next`/`last`) above `lws.container.page-size` |
| `POST` | a container | Create a contained resource; `Slug` names it, `Link: rel="type"` picks container/RDF/non-RDF; `201` + `Location` |
| `PUT` | any IRI | Create (new) or replace (existing) at that exact IRI; replacing MUST be conditional |
| `PATCH` | RDF or JSON resource | RDF: `application/merge-patch+json` (RFC 7386) or `application/sparql-update`; JSON & linkset: `application/merge-patch+json` or `application/json-patch+json` (RFC 6902) |
| `DELETE` | any resource | Delete (non-empty container → `409`, or recursive with `Depth: infinity`); removes the resource's metadata too |
| `GET`/`HEAD`/`PATCH`/`PUT`/`OPTIONS` | `<resource>.meta` | The resource's linkset (metadata) resource — see [Metadata](#metadata-linkset) |
| `OPTIONS` | any | `Allow`, `Accept-Post`, `Accept-Patch`, `Want-Content-Digest` |

Responses carry `ETag`, `Last-Modified`, and `Link` relations: `rel="type"` interaction models,
`rel="…/lws#storageDescription"`, `rel="up"` (parent container, non-root), and `rel="linkset"`
(the metadata resource). `If-None-Match`/`If-Modified-Since` (→ `304`) and `If-Match` (→ `412`) are
honoured; an unconditional PUT replacing an existing resource is refused with `428 Precondition
Required`; a write exceeding `lws.quota.max-bytes` is refused with `507 Insufficient Storage`.
Errors are returned as `application/problem+json` (RFC 9457); a `401` carries `WWW-Authenticate` and
a `rel="storageDescription"` Link so a client can discover how to authenticate. The storage description is served at
`/.lws/storage-description` as `application/lws+json` (the canonical `{id,type:"Storage",capability,
service}` document, advertising a `StorageDescription` service entry alongside the notification and
search services). Each `capability` is a **structured object** (`{type, …}`): the implemented
protocol modules (type only), a `PatchSupport` entry mapping each target media type to its accepted
PATCH formats, a `ContentNegotiation` entry listing the interchangeable RDF serialisations, and an
RFC 9530 digest entry listing the supported algorithms. RDF is available via content negotiation.

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

Present a credential in the `Authorization` header (`Bearer`, `DPoP`, or `SAML2`). A single
orchestrator routes it to the right suite by shape and returns the authenticated principal;
Apache Shiro manages the resulting subject. All four LWS suites are supported:

| Suite | Credential | Verification key comes from |
|---|---|---|
| **OpenID Connect** | signed JWT (`iss` ≠ `sub`) | the issuer's JWKS, via OIDC discovery — trusted because the subject's controlled-identifier document advertises an `lws:OpenIdProvider` service whose `serviceEndpoint` equals `iss` |
| **SSI Controlled Identifier** | self-issued JWT (`sub`=`iss`=`client_id`, an HTTPS URL) | a `verificationMethod` (`publicKeyJwk`) selected by the JWT `kid` in the dereferenced controlled-identifier document |
| **did:key** | self-issued JWT (`sub`=`iss`=`client_id`, a `did:key:` URI) | the public key encoded in the `did:key` identifier itself (Ed25519, P-256, secp256k1) — no network lookup |
| **SAML 2.0** | signed SAML assertion (optionally base64) | a pre-configured trusted IdP key (out-of-band trust); the XML signature is validated and `NameID`/`Issuer`/`Recipient` mapped to subject/issuer/client |

All JWT suites reject `alg: none` and enforce `exp`. SAML trust is configured via
`lws.saml.idp-certificates` (and optionally `lws.saml.trusted-issuers` / `lws.saml.audience`);
without a configured certificate the SAML suite is inactive. `jakartaee-pac4j` additionally
provides optional interactive OIDC sign-in for the Wicket UI when an OIDC client is configured.

**Proof-of-possession (DPoP, RFC 9449).** Use `Authorization: DPoP <access-token>` together with a
`DPoP: <proof-jwt>` header. The server verifies the proof (its `typ`, signature via the embedded
`jwk`, `htm`/`htu`, `iat` freshness, single-use `jti`, and `ath` over the access token) and
requires the access token's `cnf.jkt` to equal the proof key's JWK thumbprint — so a stolen token
is useless without the holder's private key. Plain `Bearer` tokens skip these checks.

### Authorization (Web Access Control)

Set `lws.access-control=wac` for multi-user authorization via
[Web Access Control](https://solidproject.org/TR/wac). Each resource may have an ACL resource
(`<resource>.acl`, or `<container>/.acl`), discoverable via the `Link: rel="acl"` header. ACLs are
RDF documents containing `acl:Authorization` rules:

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
  group) and checking `vcard:hasMember`, cached briefly.
- **Resolution**: a resource's own ACL (`acl:accessTo`) wins; otherwise the nearest ancestor
  container's ACL applies through `acl:default` (inheritance), up to the root. The nearest ACL
  fully overrides ancestors — there is no super-owner, so include yourself when delegating a subtree.
- **Bootstrap**: the root ACL is created at startup from `lws.owners` (Read/Write/Control + public
  Read if `lws.public-read`); with no owners the root is opened to the public (development).
- Editing an ACL requires `acl:Control` on its target (ACLs are not themselves access-controlled,
  avoiding infinite regress).

To create users, point each at their OIDC issuer (their WebID document must advertise an
`lws:OpenIdProvider` service for that issuer — see Authentication) and grant their WebID the modes
they need in the relevant ACLs.

### Notifications

Discover support in the storage description (a `NotificationService` with a `serviceEndpoint` and
`WebhookSubscription` type). Create a subscription with an authenticated POST to
`/.lws/subscriptions`:

```json
{ "type": "WebhookSubscription",
  "topic": ["http://localhost:8080/some/container/"],
  "inbox": "https://example.org/inbox",
  "expires": "2026-12-31T00:00:00Z" }
```

Container topics are recursive. The server enforces that the subscriber may read every topic, and
will not deliver a notification for a resource the subscriber cannot read. On each change it POSTs
a JSON-LD `lws:Notification` (wrapping an Activity Streams 2.0 `Create`/`Update`/`Delete`) to the
inbox, signed with RFC 9421 HTTP Message Signatures (covering `@method @scheme @authority @path
content-type content-digest`, with `created` + `keyid`). The signing public key is published at
`/.lws/jwks`. Subscriptions may declare an `expires` instant; a background task purges expired
subscriptions on the `lws.subscription.purge-interval-seconds` schedule.

### Search & Type Index

The storage description advertises a `TypeIndexService` and a `TypeSearchService`, each with a
`serviceEndpoint`. Both answer `application/lws+json`, are paginated (`?page=N` with `first`/`prev`/
`next`/`last` `Link` relations) and are **authorization-filtered for the requesting client** — a
type or resource the client cannot read never appears, and `totalItems` counts only that view, so a
client cannot discover that a private type or resource exists. Responses are `Cache-Control:
private, no-store`.

A resource's types are its structural LWS type (`lws:Container` / `lws:DataResource`) plus any
`rdf:type` its own representation asserts about itself (the resource IRI or a hash fragment of it).

- **Type index** — `GET /.lws/type-index` lists the distinct types visible to the client:
  ```json
  { "@context": "https://www.w3.org/ns/lws/v1", "type": "TypeIndex", "totalItems": 5,
    "items": [ { "id": "https://schema.org/Person" }, { "id": "https://schema.org/Event" } ] }
  ```
- **Type search** — equivalent `GET` and `POST` forms carrying a conjunctive-normal-form filter,
  returning a synthetic `ContainerPage`. In the `GET` form a comma-separated value is OR and a
  repeated parameter is AND; in the `POST` body a nested array is OR and the outer array is AND:
  ```
  GET /.lws/type-search?type=https://schema.org/Person,http://xmlns.com/foaf/0.1/Person&type=https://www.w3.org/ns/lws%23DataResource
  ```
  ```json
  POST /.lws/type-search   Content-Type: application/lws+json
  { "@context": "https://www.w3.org/ns/lws/v1",
    "type": [ ["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"],
              "https://www.w3.org/ns/lws#DataResource" ] }
  ```
  Both select `(schema:Person OR foaf:Person) AND lws:DataResource`. Beyond the mandatory `type`
  baseline, a filter key that is an **absolute-URI predicate** matches a descriptive relation read
  from the resource's representation (e.g. `&https%3A%2F%2Fex.org%2Fshape=…`); a relation the server
  does not index simply yields no matches (never an error). Errors follow the spec: `415` for a POST
  body that is not `application/lws+json`, `400` for a malformed filter / non-absolute-URI value /
  over-complex filter, and `404` for a page past the last.

### Access Requests & Grants

The storage description advertises an `AccessRequestService` and an `AccessGrantService` (each with a
`serviceEndpoint` and the `conformsTo` access profile). Both are LWS containers served as
`application/lws+json`:

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
`delete`→DELETE); `assignee` may be `http://xmlns.com/foaf/0.1/Agent` for public access; `target`
matches a resource exactly or, for a container value, its subtree. Constraints are evaluated
fail-closed — `dateTime`, `client`, `mediaType`, `type` and `purpose` are honoured (`mediaType`/
`type` from the target's metadata; `purpose` from a client-declared `LWS-Purpose` request header).
Grants never confer `Control`. On creation the server delivers a signed
`lws:Notification` (an AS2 `Create` about the new document, RFC 9421-signed like a webhook) to the
relevant inboxes: the document's own `inbox`, the configured controller inbox for a new request, and
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
(`DidKeyValidatorTest`, `SsiCidValidatorTest`, `SamlValidatorTest`, `LwsCredentialValidatorTest`):
valid Ed25519/P-256/RSA credentials are accepted and forged, expired, mismatched, untrusted-key
and untrusted-issuer credentials are rejected. The OpenID Connect suite is covered by
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
`lws:Notification` whose RFC 9421 HTTP Message Signature and RFC 9530 Content-Digest verify against
the server's published JWKS Ed25519 key — exactly what a real subscriber would check.

The Type Index / Type Search services are covered by
[`SearchIndexTest`](src/test/java/com/ebremer/lws/server/SearchIndexTest.java) (service discovery,
the type index, GET/POST search with single/OR/AND/native-container/relation filters, GET≡POST
equivalence, and the `415`/`400`/`404`/`405` error responses) and
[`SearchIndexAuthzTest`](src/test/java/com/ebremer/lws/server/SearchIndexAuthzTest.java), which runs
in owner mode with a `did:key` owner and asserts the security guarantees: an owner sees private
types and resources while an anonymous client sees neither (cannot even learn they exist), plus the
pagination `Link` relations and the out-of-range-page `404`.

Access Requests & Grants are covered by
[`AccessGrantsTest`](src/test/java/com/ebremer/lws/server/AccessGrantsTest.java): a controller's
grant lets another `did:key` agent read a resource it otherwise cannot (scoped to the granted
action), revoking the grant withdraws the access, a public (`foaf:Agent`) grant admits an anonymous
reader, `mediaType` and `purpose` constraints that gate the grant (by the target's media type and
the client-declared `LWS-Purpose`), plus the request lifecycle, controller-only grant issuance,
discovery advertisement, and the `401`/`403`/`415` cases.
[`AccessNotificationTest`](src/test/java/com/ebremer/lws/server/AccessNotificationTest.java) asserts
the signed `lws:Notification` is delivered (with a matching Content-Digest) to the document's own
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
conditional Merge-Patch/PUT), linkset removal on delete, the storage description as
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

- Tracks the LWS **Editor's Draft** (operations from the in-flux `Operations/` spec source); gaps
  are filled with LDP/Solid conventions and may change.
- Container listings are filtered per member by read authorization (`items` and `totalItems`
  reflect only the resources the client may read), so a listing is client-specific. The linkset
  resource stores its user-managed links as a JSON document and merges server-managed links on read.
- Authorization offers two modes via `lws.access-control`: single-tenant **owner/public-read**, or
  multi-user **Web Access Control** (WAC). Both sit behind a pluggable
  [`Authorizer`](src/main/java/com/ebremer/lws/server/core/Authorizer.java) (the LWS core draft
  leaves authorization unspecified, so WAC follows the Solid conventions). WAC supports
  `acl:agent`, `acl:agentClass`, `acl:agentGroup`, and `acl:origin` (browser/app-scoped access via
  the request's `Origin`).
- PATCH supports `application/merge-patch+json` (RFC 7386 — the LWS-required format) and
  `application/sparql-update`. Merge Patch applies directly to JSON (non-RDF) resources and to RDF
  resources via their JSON-LD representation (so for RDF it is most predictable on simple/single-node
  shapes; use SPARQL Update for precise graph edits). **JSON Patch** (RFC 6902,
  `application/json-patch+json`) is additionally accepted for JSON (non-RDF) and linkset resources (a
  failed `test` operation or an unresolvable JSON Pointer yields `409`); it is not offered for RDF
  resources, whose JSON-LD shape is not a stable pointer target. SPARQL Update `LOAD`/`SERVICE` (which
  would make the server fetch a URL — an SSRF vector) are blocked unless their host is in
  `lws.sparql-update.allowed-hosts`. N3 Patch (`text/n3`) is intentionally not implemented — the LWS
  Editor's Draft does not require it (JSON Merge Patch is the only PATCH format a server must support).
- DPoP is enforced for the `DPoP` scheme (RFC 9449: proof signature, `htm`/`htu`, `iat` freshness,
  `jti` replay, `ath`, and `cnf.jkt` binding), with optional server-issued nonces (§8) via
  `lws.dpop.require-nonce` — a nonceless request is answered `401` + `DPoP-Nonce`. The `jti` replay
  cache (a bounded, TTL-evicting [Caffeine](https://github.com/ben-manes/caffeine) cache, as are the
  OIDC trust/JWKS and WAC agentGroup caches) and the (stateless HMAC) nonce secret are per-process; a
  shared cache/secret would be needed across a cluster.
- **Outbound-fetch SSRF guard.** Authentication dereferences URLs from untrusted token claims (the
  WebID/CID `sub`, the OIDC issuer `iss` and its JWKS) and WAC dereferences `acl:agentGroup`
  documents. These are gated by an `OutboundFetchPolicy`: non-`http(s)` schemes are always refused
  (closing `file://` local-file reads via Jena's loader), and by default hosts resolving to loopback,
  private, link-local (incl. the cloud-metadata `169.254.169.254`), wildcard or multicast addresses
  are blocked (`lws.fetch.block-private-addresses`, with a `lws.fetch.allowed-hosts` exemption for an
  internal IdP). `HttpDocumentLoader` also caps document size (2 MiB) and time-bounds the request.
  Only the presented URL is checked, not HTTP redirect targets — the underlying loaders follow
  redirects — so deploy where the server cannot reach sensitive internal endpoints.
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
- Access **grants** are enforced for their `action`/`assignee`/`target` and all constraint types
  (`dateTime`/`client`/`mediaType`/`type`/`purpose`). `acl:origin` and the `purpose` (`LWS-Purpose`
  header) are **client-declared**, not cryptographically attested — as is the nature of
  origin/purpose policy.
- The Type Index / Type Search services serve resource **types** from an in-memory derived index,
  built lazily on first use and maintained incrementally from resource events (create/update/delete);
  relation targets are not cached and are queried on demand for the predicates a search needs. Per
  lws10-searchindex, type/relation membership may be eventually consistent — though synchronous event
  delivery makes it read-your-writes in practice. **Authorization is never cached**: it is applied
  live, per request, over the index, so a revoked grant takes effect immediately, and `totalItems`
  counts only the requesting client's authorized view. Descriptive-relation filtering is limited to
  relations expressed as absolute-URI predicates in the resource's own representation;
  structural/protocol relations are never indexed.
- `buji-pac4j` is intentionally **not** used: its current release pulls the `javax`-servlet pac4j
  module, which is incompatible with this Jakarta (Servlet 6 / Jetty 12) stack. Shiro is wired
  directly instead.
