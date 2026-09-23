---
title: Configuration
nav_order: 4
---

# Configuration
{: .no_toc }

1. TOC
{:toc}

## How configuration is resolved

Settings are resolved (lowest to highest precedence) from:

1. built-in defaults,
2. `lws.properties` on the classpath,
3. `./lws.properties` in the working directory,
4. `-Dlws.*` JVM system properties.

A starter file with every key and inline guidance ships as
[`lws.example.properties`](https://github.com/ebremer/lws-server/blob/master/lws.example.properties) —
copy it to `lws.properties` and edit. The tables below cover every settings group; the
[README's configuration table](https://github.com/ebremer/lws-server#configuration) and the example
file are the complete per-key reference.

### Fail-fast validation

Invalid values **fail fast** at startup with an actionable message naming the key, the value, and
what was expected — for example an out-of-range port, an unknown enum (the message lists the allowed
values), a non-`true`/`false` flag, or a malformed `lws.base-uri` — rather than a raw parse exception.
Booleans are strict (`true`/`false` only). Unsafe combinations are refused too: no `lws.owners`
without `lws.dev.open=true`, `lws.dev.open` together with `lws.require-https`, and
`lws.cors.allowed-origins=*` in open mode. The bare-Jetty launcher prints the message and exits
without a stack trace.

## Core

| Property | Default | Meaning |
|---|---|---|
| `lws.base-uri` | `http://localhost:8080` | Public base IRI of the storage. Must be an `http(s)` URL; it may carry a path (`https://host/lws`) when a proxy publishes the server under one — see [Deployment](deployment.md#under-a-path-prefix). In production set it to the external `https://` URL — every minted IRI, DPoP `htu`, WebID, ACL and the authorization server's issuer derive from it. |
| `lws.listen-port` | port of `lws.base-uri`, else `8080` | HTTP listen port, when it differs from the base URI's — typically behind a reverse proxy, where the base URI is the external address. |
| `lws.data-dir` | `lws-data` | Directory for the TDB2 dataset, binary blobs and signing keys (key directories are made owner-only at startup). |
| `lws.system-prefix` | `.lws` | Path prefix for the server's own endpoints (storage description, token endpoint, JWKS, subscriptions, search, access requests/grants). Reserved: no resource may be created under it. |
| `lws.owners` | *(empty)* | Space/comma-separated owner WebIDs/DIDs. **Empty ⇒ the server refuses to start** unless `lws.dev.open=true`. |
| `lws.dev.open` | `false` | Permit the development-only postures: an empty `lws.owners` (open mode — everything permitted for everyone) and `lws.ui.dev-login` on a non-loopback base URI. |
| `lws.public-read` | `false` | Whether non-owners may read the storage **at all** — storage-wide, not per resource. To open one resource or subtree, issue an access grant to `foaf:Agent` instead. |
| `lws.access-control` | `OWNER` | `OWNER` (single-tenant owner/public-read) or `WAC` (multi-user [Web Access Control](authorization.md)). |
| `lws.wac.group-cache-seconds` / `.group-failure-cache-seconds` / `.max-group-fetches-per-decision` | `300` / `30` / `8` | WAC: reuse of resolved `acl:agentGroup` documents, retry delay for unreachable ones, and how many one decision may fetch. |
| `lws.mask-forbidden-as-not-found` | `true` | Answer an *authenticated* principal without Read `404` whether or not the resource exists (anonymous clients still get `401`). |

## RDF backend

| Property | Default | Meaning |
|---|---|---|
| `lws.sparql.mode` | `TDB2` | `TDB2` (embedded) or `REMOTE` (any SPARQL 1.1 service — experimental). |
| `lws.sparql.query` / `.update` / `.gsp` | | **Required** when `mode=REMOTE`: Query / Update / Graph Store Protocol endpoints, absolute `http(s)` URLs. |
| `lws.sparql.remote.accept-no-transactions` | `false` | Must be `true` to run `REMOTE`. Remote SPARQL has no transactions, so conditional writes, atomic deletes (with the ACL and linkset), the quota and `Slug` uniqueness become best-effort. |

## Authorization server & access tokens

The storage embeds an OAuth 2.0 authorization server, per the LWS core Authorization section. See
[Authentication](authentication.md).

| Property | Default | Meaning |
|---|---|---|
| `lws.oauth.enabled` | `true` | Run the embedded authorization server: Token Exchange (RFC 8693) at `<system-prefix>/token`, RFC 8414 metadata at `/.well-known/lws-configuration`, signing key at `<system-prefix>/jwks`. Its issuer is `lws.base-uri`. |
| `lws.oauth.access-token-lifetime-seconds` | `300` | Lifetime of the RFC 9068 access tokens it issues (1–3600), never longer than the exchanged credential. |
| `lws.oauth.trusted-issuers` | | External authorization servers whose RFC 9068 access tokens are also accepted (metadata read from their `/.well-known/lws-configuration`). |
| `lws.oauth.accept-authentication-credentials` | `true` | Also accept an authentication credential presented directly as the `Authorization` token (the pre-baseline behaviour). |

## Authentication

| Property | Default | Meaning |
|---|---|---|
| `lws.audience` | this storage's IRI (`lws.base-uri`, with and without a trailing `/`) | Accepted `aud` values for JWT credentials (comma/space separated). A credential naming another audience is always refused. |
| `lws.audience.require` | `true` | Refuse a JWT credential with no `aud` at all. |
| `lws.token.max-lifetime-seconds` | `3600` | Max lifetime of a self-signed (SSI-CID, including `did:key`) credential (`0` = unlimited). |
| `lws.ssi-cid.document-cache-seconds` / `.document-failure-cache-seconds` | `300` / `30` | How long an SSI-CID subject document is reused (also how long a revoked key stays honoured), and the retry delay for an unreachable one. |
| `lws.saml.idp-certificates` | | PEM/DER X.509 certificate paths of trusted SAML IdPs (enables the SAML suite). |
| `lws.saml.trusted-issuers` / `lws.saml.audience` | | Optional SAML issuer allow-list / expected audience. |
| `lws.dpop.require-nonce` | `false` | Require a server-issued nonce in DPoP proofs (RFC 9449 §8). |
| `lws.dpop.require` | `false` | Refuse plain `Bearer` entirely (a DPoP-bound token is always refused as `Bearer`). |
| `lws.dpop.jti-cache-size` | `100000` | DPoP proof ids retained for replay detection. |
| `lws.oidc.discovery-uri` / `.client-id` / `.client-secret` | | Enable interactive OpenID Connect single sign-on for the [management UI](management-ui.md). |
| `lws.ui.dev-login` | `false` | Enable the UI's developer sign-in (WebID impersonation; **dev only** — loopback base URI only unless `lws.dev.open=true`). |

## Notifications

| Property | Default | Meaning |
|---|---|---|
| `lws.webhook.max-attempts` / `.retry-backoff-ms` | `5` / `2000` | Delivery attempts for retryable outcomes (5xx, 429, transient I/O), and the backoff between them (multiplied by the attempt number). |
| `lws.webhook.threads` / `.queue-capacity` / `.max-in-flight-per-host` | `4` / `1000` / `4` | Delivery workers, deliveries allowed to wait, and deliveries in flight to one inbox host. |
| `lws.webhook.max-consecutive-failures` | `10` | Consecutive failures before a subscription is deactivated. |
| `lws.subscription.purge-interval-seconds` | `3600` | How often expired subscriptions are purged (`0` disables). |
| `lws.subscriptions.allow-anonymous` | `false` | Allow unauthenticated subscription creation. |
| `lws.subscriptions.max-per-subscriber` / `.max-lifetime-seconds` | `100` / `2592000` | Subscriptions one subscriber may hold (then `429`), and the maximum/default lifetime (`0` = no expiry imposed). |
| `lws.notifications.include-actor` | `false` | Name the agent that made a change in notifications (LWS core: omitted by default). |

## Search & access

| Property | Default | Meaning |
|---|---|---|
| `lws.search-index.enabled` | `true` | Advertise and serve the [Type Index / Type Search](search-type-index.md) services. |
| `lws.search-index.page-size` | `100` | Max items per Type Index / Type Search response page. |
| `lws.container.page-size` | `1000` | Max members per container-listing page (larger listings are paginated). |
| `lws.access-requests.enabled` | `true` | Advertise and serve the [Access Request / Access Grant](authorization.md) services. |
| `lws.access-requests.controller-inbox` | | Inbox notified when a new access request is created. |

## Browser access (CORS)

| Property | Default | Meaning |
|---|---|---|
| `lws.cors.allowed-origins` | *(empty)* | Web origins allowed to call the API from a browser. Empty means **no cross-origin access** — no `Access-Control-*` header is sent. `*` is allowed (credentials are never sent) but refused in open mode. `/app` and `/callback` are never CORS-enabled. |
| `lws.cors.max-age-seconds` | `600` | How long a browser may cache a preflight. |

## Limits & integrity

| Property | Default | Meaning |
|---|---|---|
| `lws.quota.max-bytes` | `0` | Max total binary-content bytes (`0` = unlimited); over-quota writes get `507`. |
| `lws.max-request-bytes` | `67108864` | Max request-body size (`0` = unlimited); larger requests get `413`. |
| `lws.linkset.max-bytes` | `1048576` | Max serialized size of one resource's user-managed linkset (`.meta`); a write whose result would exceed it gets `400`. |

## SSRF guards

| Property | Default | Meaning |
|---|---|---|
| `lws.sparql-update.allowed-hosts` | | Hosts a SPARQL Update `LOAD`/`SERVICE` may fetch (empty = blocked entirely). |
| `lws.fetch.block-private-addresses` | `true` | Block auth/WAC dereferences to private/loopback/link-local (incl. cloud-metadata) addresses. |
| `lws.fetch.allowed-hosts` | | Hosts exempt from that block (e.g. an internal IdP). |
| `lws.webhook.block-private-addresses` | `true` | Block notification delivery to private/loopback/metadata inbox addresses. |
| `lws.webhook.allowed-hosts` | | Inbox hosts exempt from that block. |
| `lws.jsonld.allowed-context-hosts` | | Hosts whose JSON-LD `@context` may be fetched (empty = remote contexts refused; inline contexts always work). |

See [Security](security.md) for what these protect against.

## Embedded SPARQL endpoint

| Property | Default | Meaning |
|---|---|---|
| `lws.sparql.endpoint.enabled` | `false` | Expose an embedded [Fuseki SPARQL endpoint](sparql-endpoint.md) over the local dataset. |
| `lws.sparql.endpoint.port` / `.dataset` / `.read-only` / `.loopback` | `3030` / `lws` / `true` / `true` | Port, dataset path, query-only, loopback-only. |
| `lws.sparql.endpoint.public-url` | | Query URL advertised in the storage description (else derived from base host/port). |

## Deployment & TLS

See [Deployment & TLS](deployment.md) for the full setup.

| Property | Default | Meaning |
|---|---|---|
| `lws.behind-proxy` | `false` | Trust `X-Forwarded-*` / `Forwarded` (RFC 7239) from a fronting TLS-terminating proxy. |
| `lws.require-https` | `false` | Refuse to start unless `lws.base-uri` is `https://` (loopback exempt). |
| `lws.hsts.max-age-seconds` | `31536000` | `Strict-Transport-Security` lifetime, sent only on responses that went out over TLS for an `https` base URI (`0` = off). |
| `lws.tls.enabled` | `false` | Terminate TLS in the server, provisioning a certificate via ACME (bare-Jetty launcher only; ignored, with a warning, by the Spring Boot entry point). |
| `lws.tls.port` / `lws.tls.http-port` | `443` / `80` | HTTPS port, and the HTTP port serving the ACME challenge + redirect. |
| `lws.tls.acme.directory-url` | Let's Encrypt prod | ACME directory URL (use the staging URL for testing). |
| `lws.tls.acme.domains` | base-URI host | Domain(s) to certify (space/comma separated). |
| `lws.tls.acme.email` | | Contact email for the ACME account. |
| `lws.tls.acme.accept-terms-of-service` | `false` | MUST be `true` to register (agrees to the CA's Terms of Service). |
| `lws.tls.acme.renew-before-days` / `lws.tls.dir` | `30` / `<data>/tls` | Renewal lead time; directory for the account key, domain key and certificate. |

{: .warning }
> An empty `lws.owners` is **open mode** — every read, write and control decision permitted for every
> client, anonymous ones included — and the server only runs that way with `lws.dev.open=true`. Never
> use it on a reachable host.
