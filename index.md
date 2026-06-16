---
title: Home
nav_order: 1
---

# LWS Server

A [Linked Web Storage](https://w3c.github.io/lws-protocol/) (LWS) server implementing the W3C LWS
Protocol, written as plain Jakarta servlets and bootstrapped (for now) by Spring Boot on an embedded
Eclipse Jetty container.

It is a personal storage server: clients create, read, update and delete RDF and binary resources
organised into containers, authenticate with any of the LWS credential suites, and the owner (or
fine-grained access rules) decide who may do what.

## What it implements

- **[LWS Core](https://w3c.github.io/lws-protocol/lws10-core/)** — the resource/containment model and CRUD operations.
- **[LWS Vocabulary](https://w3c.github.io/lws-protocol/lws10-vocab/)** — the `https://www.w3.org/ns/lws#` terms.
- **Authentication** — all four LWS suites:
  [OpenID Connect](https://w3c.github.io/lws-protocol/lws10-authn-openid/),
  [SAML 2.0](https://w3c.github.io/lws-protocol/lws10-authn-saml/),
  [Self-signed Controlled Identifier](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/), and
  [Self-signed did:key](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/) — plus
  proof-of-possession via DPoP.
- **[Notifications](https://w3c.github.io/lws-protocol/lws10-notifications/)** — webhook subscriptions with RFC 9421 HTTP Message Signatures.
- **[Search & Type Index](https://w3c.github.io/lws-protocol/lws10-searchindex/)** — `TypeIndexService` and `TypeSearchService`, authorization-filtered per client.
- **[Access Requests & Grants](https://w3c.github.io/lws-protocol/lws10-core/#access-requests)** — ODRL-based, enforced and revocable.
- **Web Access Control** — multi-user authorization as an alternative to single owner/public-read.

## Standards

| Area | Standard |
|---|---|
| Resource & containment model | LWS Core, LDP / Solid conventions |
| RDF metadata + linkset | RDF 1.1, [RFC 9264](https://www.rfc-editor.org/rfc/rfc9264) Linksets |
| Patch formats | [RFC 7386](https://www.rfc-editor.org/rfc/rfc7386) Merge Patch, [RFC 6902](https://www.rfc-editor.org/rfc/rfc6902) JSON Patch, SPARQL 1.1 Update |
| Conditional / range requests | RFC 9110, [RFC 7233](https://www.rfc-editor.org/rfc/rfc7233) |
| Errors | [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem+json |
| Integrity | [RFC 9530](https://www.rfc-editor.org/info/rfc9530/) Digest Fields |
| Auth | OpenID Connect, SAML 2.0, [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP |
| Notifications | [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures, Activity Streams 2.0 |
| Preferences | [RFC 7240](https://www.rfc-editor.org/rfc/rfc7240) Prefer |
| TLS provisioning | ACME ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)) via acme4j |

## Start here

- **[Getting Started](getting-started.md)** — build, run, make your first request, mint the first owner.
- **[Architecture](architecture.md)** — how the server is wired and where data lives.
- **[Configuration](configuration.md)** — every `lws.*` setting.
- **[HTTP API](http-api.md)** — methods, headers, content negotiation, discovery, integrity.
- **[Security](security.md)** — the consolidated security model and its limits.

> **Tracking an evolving spec.** The LWS core operations are implemented from the normative
> `Operations/` source in the [spec repository](https://github.com/w3c/lws-protocol/tree/main/lws10-core/Operations),
> which is ahead of the rendered Editor's Draft. Where the draft is silent, the implementation follows
> the LDP / Solid conventions it derives from (trailing-slash containers, `Link: rel="type"`
> interaction models, content negotiation, conditional requests). Because the source is in flux, some
> details may change.
