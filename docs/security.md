---
title: Security
nav_order: 13
---

# Security
{: .no_toc }

A consolidated view of the server's security model and its known limits. The detailed pages are
linked from each item.

1. TOC
{:toc}

## Open mode

With **no `lws.owners` configured the server runs in open mode** — all reads and writes are
permitted. Set owners (and consider [WAC](authorization.md)) before exposing the server. The server
logs a warning at startup when running open.

## Transport security (TLS)

DPoP and WebID/OIDC assume TLS in production. Either run [behind a TLS-terminating reverse
proxy](deployment.md) (`lws.behind-proxy=true`, `lws.base-uri` set to the external `https://` URL) or
let the [bare-Jetty launcher terminate TLS](deployment.md) via ACME/Let's Encrypt
(`lws.tls.enabled=true`). `lws.require-https=true` makes the server refuse to start on a non-HTTPS,
non-loopback base URI.

## Authentication & proof-of-possession

All JWT [credential suites](authentication.md) reject `alg: none` and enforce `exp`. **DPoP**
(RFC 9449) binds a token to the holder's key (`cnf.jkt` = proof JWK thumbprint), with `htm`/`htu`,
`iat` freshness, single-use `jti` replay protection, and `ath` over the access token; optional
server-issued nonces (§8) are available via `lws.dpop.require-nonce`.

## SSRF guards

The server makes outbound HTTP requests in two places, both from partly-untrusted input — each is
guarded:

- **Auth & WAC dereferences** — the WebID/CID `sub`, OIDC `iss` and its JWKS, and `acl:agentGroup`
  documents are gated by an `OutboundFetchPolicy`: non-`http(s)` schemes are always refused (closing
  `file://` local-file reads), and by default hosts resolving to loopback, private, link-local (incl.
  the cloud-metadata `169.254.169.254`), wildcard or multicast addresses are blocked
  (`lws.fetch.block-private-addresses`, with a `lws.fetch.allowed-hosts` exemption). The document
  loader also caps body size (2 MiB) and time-bounds the request.
- **SPARQL Update `LOAD` / `SERVICE`** — blocked unless the target host is in
  `lws.sparql-update.allowed-hosts` (empty by default ⇒ blocked entirely). See the
  [SPARQL endpoint](sparql-endpoint.md) page.

> **Residual risk.** Only the *presented* URL is checked, not HTTP redirect targets — the underlying
> loaders follow redirects, so a public host that 30x-redirects to an internal address is not fully
> prevented. Deploy where the server cannot reach sensitive internal endpoints, and keep the
> allow-lists tight.

## Integrity

[RFC 9530](http-api.md#integrity--rfc-9530-digest-fields) `Content-Digest` is verified on writes that
carry it (mismatch ⇒ `400`), and `Repr-Digest`/`Content-Digest` are served on demand. Only the
RFC-recommended `sha-256` / `sha-512` are produced or verified; the obsolete `md5`/`sha`/`unixsum`/
`crc32c` are not. Webhook deliveries and access-event notifications are signed with
[RFC 9421](notifications.md) HTTP Message Signatures (verifiable against `/.lws/jwks`).

## Quota

`lws.quota.max-bytes` caps total binary-content bytes (`0` = unlimited); over-quota writes get `507`.
RDF graph storage is not metered.

## Caches

The DPoP `jti` replay cache, the OIDC trust/JWKS caches and the WAC agentGroup cache are bounded,
TTL-evicting in-process caches (Caffeine). They — and the stateless-HMAC DPoP nonce secret — are
**per-process**; a clustered deployment would need a shared store. (The search service's derived type
index is likewise in-memory, but it is a complete materialized view rather than an evictable cache.)

## Things that are client-declared (not attested)

`acl:origin` and the access-grant `purpose` (`LWS-Purpose` header) are **client-declared**, not
cryptographically attested — as is the nature of origin/purpose policy. Treat them as advisory scoping,
not as a security boundary against a hostile client.

## The embedded SPARQL endpoint bypasses authorization

If enabled, the [embedded Fuseki endpoint](sparql-endpoint.md) operates on the whole dataset and
**bypasses WAC/owner authorization**, exposing internal administrative graphs. It is disabled by
default, and when enabled is query-only and loopback-bound unless reconfigured. Treat it as a trusted
endpoint.
