---
title: Home
nav_order: 1
---

# LWS Server

A [Linked Web Storage](https://w3c.github.io/lws-protocol/) (LWS) server implementing the W3C LWS
Protocol, written as plain Jakarta servlets and bootstrapped (for now) by Spring Boot on an embedded
Eclipse Jetty container.

It is a personal storage server: clients create, read, update and delete RDF and binary resources
organised into containers, authenticate with any of the LWS credential suites, exchange that
credential for an access token at the storage's own authorization server, and the owner (or
fine-grained access rules) decide who may do what.

## What it implements

- **[LWS Core](https://w3c.github.io/lws-protocol/lws10-core/)** — the resource/containment model and
  CRUD operations, and the storage description as a Controlled Identifier document
  (`application/lws+cid`) served at the storage URI.
- **[LWS Vocabulary](https://w3c.github.io/lws-protocol/lws10-vocab/)** — the `https://www.w3.org/ns/lws#` terms.
- **[LWS Authorization](https://w3c.github.io/lws-protocol/lws10-core/#authorization)** — the OAuth 2.0
  baseline: an embedded authorization server (Token Exchange, RFC 8693; metadata at
  `/.well-known/lws-configuration`) issuing RFC 9068 access tokens for this storage, validation of
  those tokens (and of trusted external servers'), and `as_uri`/`realm` challenges on `401`.
- **Authentication** — the three current LWS suites:
  [OpenID Connect](https://w3c.github.io/lws-protocol/lws10-authn-openid/),
  [SAML 2.0](https://w3c.github.io/lws-protocol/lws10-authn-saml/), and
  [Self-signed Controlled Identifier](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/)
  (HTTPS, `did:key` and `did:web` subjects) — plus proof-of-possession via DPoP. The discontinued
  [self-signed did:key](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/) suite's
  credentials are still accepted, deprecated.
- **[Notifications](https://w3c.github.io/lws-protocol/lws10-core/#notifications)** — the core
  notification data model and the [webhook suite](https://w3c.github.io/lws-protocol/lws10-notifications-webhook/),
  signed with RFC 9421 HTTP Message Signatures verifiable from the storage description.
- **[Search & Type Index](https://w3c.github.io/lws-protocol/lws10-index/)** — the `TypeIndexService`
  and the `QUERY`-based `TypeSearchService`, authorization-filtered per client.
- **[Access Requests & Grants](https://w3c.github.io/lws-protocol/lws10-core/#access-requests-and-grants)** — ODRL-based, enforced and revocable.
- **Web Access Control** — multi-user authorization as an alternative to single owner/public-read.

## Standards

| Area | Standard |
|---|---|
| Resource & containment model | LWS Core, LDP / Solid conventions |
| Storage description | [Controlled Identifiers 1.0](https://www.w3.org/TR/cid-1.0/) (`application/lws+cid`) |
| RDF metadata + linkset | RDF 1.1, [RFC 9264](https://www.rfc-editor.org/rfc/rfc9264) Linksets |
| Patch formats | [RFC 7386](https://www.rfc-editor.org/rfc/rfc7386) Merge Patch, [RFC 6902](https://www.rfc-editor.org/rfc/rfc6902) JSON Patch, SPARQL 1.1 Update |
| Conditional / range requests | RFC 9110, [RFC 7233](https://www.rfc-editor.org/rfc/rfc7233) |
| Search | the HTTP `QUERY` method with `application/lws-query+json` |
| Errors | [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem+json |
| Integrity | [RFC 9530](https://www.rfc-editor.org/info/rfc9530/) Digest Fields |
| Authorization | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) Token Exchange, [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access tokens, [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) server metadata |
| Authentication | OpenID Connect, SAML 2.0, [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP |
| Notifications | [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures, Activity Streams 2.0 |
| Preferences | [RFC 7240](https://www.rfc-editor.org/rfc/rfc7240) Prefer |
| TLS provisioning | ACME ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)) via acme4j |

## Start here

- **[Getting Started](getting-started.md)** — build, run, mint the first owner, make your first requests.
- **[Architecture](architecture.md)** — how the server is wired and where data lives.
- **[Configuration](configuration.md)** — the `lws.*` settings.
- **[HTTP API](http-api.md)** — methods, headers, content negotiation, discovery, integrity.
- **[Deployment & TLS](deployment.md)** — behind a reverse proxy (at the root or under a path), or with built-in Let's Encrypt.
- **[Security](security.md)** — the consolidated security model and its limits.

> **Specification baseline.** The server follows the LWS editor's drafts as of **21 September 2026**
> (`w3c/lws-protocol` @ `3ddc642`). [COMPLIANCE.md](https://github.com/ebremer/lws-server/blob/master/COMPLIANCE.md)
> in the repository records what changed since the previous baseline and where the server departs
> from the drafts, deliberately. Where the drafts are still silent the implementation follows the
> LDP / Solid conventions it derives from (trailing-slash containers, `Link: rel="type"` interaction
> models, content negotiation, conditional requests). The drafts are in flux, so some details may
> change.
