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

A starter file with every key and inline guidance ships as `lws.example.properties` — copy it to
`lws.properties` and edit.

### Fail-fast validation

Invalid values **fail fast** at startup with an actionable message naming the key, the value, and
what was expected — for example an out-of-range port, an unknown enum (the message lists the allowed
values), a non-`true`/`false` flag, or a malformed `lws.base-uri` — rather than a raw parse exception.
Booleans are strict (`true`/`false` only). The bare-Jetty launcher prints the message and exits
without a stack trace.

## Core

| Property | Default | Meaning |
|---|---|---|
| `lws.base-uri` | `http://localhost:8080` | Public base IRI; also sets the listen port. Must be an `http(s)` URL. In production set it to the external `https://` URL — every minted IRI, DPoP `htu`, WebID and ACL derives from it. |
| `lws.data-dir` | `lws-data` | Directory for the TDB2 dataset, binary blobs and signing keys. |
| `lws.system-prefix` | `.lws` | Path prefix for server-managed system resources (storage description, subscriptions, JWKS, search, access). |
| `lws.owners` | *(empty)* | Space/comma-separated owner WebIDs/DIDs. **Empty ⇒ open dev mode** (all reads and writes permitted). |
| `lws.public-read` | `true` | Default public-readability for newly created resources. |
| `lws.access-control` | `OWNER` | `OWNER` (single-tenant owner/public-read) or `WAC` (multi-user [Web Access Control](authorization.md)). |

## RDF backend

| Property | Default | Meaning |
|---|---|---|
| `lws.sparql.mode` | `TDB2` | `TDB2` (embedded) or `REMOTE` (any SPARQL 1.1 service). |
| `lws.sparql.query` / `.update` / `.gsp` | | Query / Update / Graph Store Protocol endpoints when `mode=REMOTE`. |

## Authentication

| Property | Default | Meaning |
|---|---|---|
| `lws.oidc.discovery-uri` / `.client-id` / `.client-secret` | | Enable interactive OIDC single sign-on for the [management UI](management-ui.md). |
| `lws.ui.dev-login` | `false` | Enable the UI's developer sign-in (WebID impersonation; **dev only**). |
| `lws.saml.idp-certificates` | | PEM/DER X.509 certificate paths of trusted SAML IdPs (enables the SAML suite). |
| `lws.saml.trusted-issuers` / `lws.saml.audience` | | Optional SAML issuer allow-list / expected audience. |
| `lws.dpop.require-nonce` | `false` | Require a server-issued nonce in DPoP proofs ([RFC 9449 §8](authentication.md)). |

## Notifications

| Property | Default | Meaning |
|---|---|---|
| `lws.webhook.max-attempts` | `5` | Webhook delivery retries. |
| `lws.webhook.max-consecutive-failures` | `10` | Consecutive failures before a subscription is deactivated. |
| `lws.subscription.purge-interval-seconds` | `3600` | How often expired subscriptions are purged (`0` disables). |

## Search & access

| Property | Default | Meaning |
|---|---|---|
| `lws.search-index.enabled` | `true` | Advertise and serve the [Type Index / Type Search](search-type-index.md) services. |
| `lws.search-index.page-size` | `100` | Max items per Type Index / Type Search response page. |
| `lws.container.page-size` | `1000` | Max members per container-listing page (larger listings are paginated). |
| `lws.access-requests.enabled` | `true` | Advertise and serve the [Access Request / Access Grant](authorization.md) services. |
| `lws.access-requests.controller-inbox` | | Inbox notified when a new access request is created. |

## Limits & integrity

| Property | Default | Meaning |
|---|---|---|
| `lws.quota.max-bytes` | `0` | Max total binary-content bytes (`0` = unlimited); over-quota writes get `507`. |

## SSRF guards

| Property | Default | Meaning |
|---|---|---|
| `lws.sparql-update.allowed-hosts` | | Hosts a SPARQL Update `LOAD`/`SERVICE` may fetch (empty = blocked entirely). |
| `lws.fetch.block-private-addresses` | `true` | Block auth/WAC dereferences to private/loopback/link-local (incl. cloud-metadata) addresses. |
| `lws.fetch.allowed-hosts` | | Hosts exempt from that block (e.g. an internal IdP). |

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
| `lws.tls.enabled` | `false` | Terminate TLS in the server, provisioning a certificate via ACME (bare-Jetty launcher only). |
| `lws.tls.port` / `lws.tls.http-port` | `443` / `80` | HTTPS port, and the HTTP port serving the ACME challenge + redirect. |
| `lws.tls.acme.directory-url` | Let's Encrypt prod | ACME directory URL (use the staging URL for testing). |
| `lws.tls.acme.domains` | base-URI host | Domain(s) to certify (space/comma separated). |
| `lws.tls.acme.email` | | Contact email for the ACME account. |
| `lws.tls.acme.accept-terms-of-service` | `false` | MUST be `true` to register (agrees to the CA's Terms of Service). |
| `lws.tls.acme.renew-before-days` / `lws.tls.dir` | `30` / `<data>/tls` | Renewal lead time; directory for the account key, domain key and certificate. |

{: .warning }
> With no `lws.owners` configured the server runs in **open mode** — all reads and writes are
> permitted. Set owners (and consider `WAC`) before exposing the server.
