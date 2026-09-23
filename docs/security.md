---
title: Security
nav_order: 13
---

# Security
{: .no_toc }

A consolidated view of the server's security model and its known limits. The detailed pages are
linked from each item. To report a vulnerability, see `SECURITY.md` in the repository (privately, to
the maintainer — not as a public issue).

1. TOC
{:toc}

## No open mode by accident

The server **refuses to start with no `lws.owners`**. An empty owner list is *open mode* — every
read, write and control decision permitted for every client, anonymous included — and it has to be
asked for explicitly with `lws.dev.open=true`, which is refused together with
`lws.require-https=true` and warned about off loopback. Open mode also has no storage controller, so
[access grants](access-requests.md) cannot be issued in it. `lws.public-read` defaults to `false`.
See [Authorization](authorization.md).

## Transport security (TLS)

DPoP and WebID/OIDC assume TLS in production. Either run [behind a TLS-terminating reverse
proxy](deployment.md) (`lws.behind-proxy=true`, `lws.base-uri` set to the external `https://` URL) or
let the [bare-Jetty launcher terminate TLS](deployment.md) via ACME/Let's Encrypt
(`lws.tls.enabled=true`). `lws.require-https=true` makes the server refuse to start on a non-HTTPS,
non-loopback base URI. `Strict-Transport-Security` (`lws.hsts.max-age-seconds`, default one year) is
sent only on responses that actually went out over TLS, and only when the base URI is `https`.

## Authentication, tokens & proof-of-possession

- **Access tokens** from the embedded authorization server are RFC 9068 `at+jwt`, `ES256`, 300 s by
  default, audience-bound to exactly this storage, and never outlive the credential they were
  exchanged for. The signing key is kept owner-only in `<data-dir>/keys/`. Tokens from other
  authorization servers are accepted only from `lws.oauth.trusted-issuers`. See
  [Authentication](authentication.md).
- **Credentials** — all JWT suites reject `alg: none` and enforce `exp`; every JWT credential must
  name this storage in `aud` (`lws.audience`, `lws.audience.require`), which stops replay against
  another storage; self-signed credentials are capped at `lws.token.max-lifetime-seconds`. SAML is
  profiled against signature wrapping (one assertion, one enveloped signature bound to it).
  `lws.oauth.accept-authentication-credentials=false` limits the storage to access tokens.
- **DPoP** (RFC 9449) binds a token to the holder's key (`cnf.jkt` = proof JWK thumbprint), with
  `htm`/`htu`, `iat` freshness, single-use `jti` replay protection, and `ath` over the access token;
  a bound token presented as `Bearer` is refused; optional server-issued nonces (§8) via
  `lws.dpop.require-nonce`; `lws.dpop.require=true` refuses plain `Bearer` entirely.

## Information disclosure

- With `lws.mask-forbidden-as-not-found` (default `true`) an authenticated principal without Read
  gets `404` for a resource that exists, just as for one that does not. An anonymous client still
  gets `401`, so it can discover how to authenticate; under WAC the anonymous `401`/`404` split can
  still reveal where ACLs sit.
- Container listings, the type index and type search show each client only what it may read; the
  authorization check is applied live per request, never cached.
- **CORS is off until configured.** `lws.cors.allowed-origins` is empty by default. A preflight is
  answered with a fixed method and header set, `Access-Control-Allow-Credentials` is never sent, and
  `*` is refused at startup in open mode.

## SSRF guards

The server makes outbound HTTP requests from partly-untrusted input in several places; each is
guarded:

- **Auth & WAC dereferences** — the WebID/CID `sub`, `did:web` documents, the OIDC `iss` and its
  JWKS, external authorization-server metadata, and `acl:agentGroup` documents are gated by an
  `OutboundFetchPolicy`: non-`http(s)` schemes are always refused (closing `file://` local-file
  reads), and by default hosts resolving to loopback, private, link-local (incl. the cloud-metadata
  `169.254.169.254`), wildcard or multicast addresses are blocked
  (`lws.fetch.block-private-addresses`, with a `lws.fetch.allowed-hosts` exemption). The document
  loader caps the body at 2 MiB, bounds the whole exchange at 20 s, and follows redirects itself so
  that the policy is re-applied to each of at most five hops.
- **Notification delivery** — a subscription's (or access request's) `inbox` is client-supplied and
  the server POSTs signed notifications to it. Inboxes are checked by the same kind of policy at
  creation (`400`) and again before every delivery, under a separate switch
  (`lws.webhook.block-private-addresses`, exemptions in `lws.webhook.allowed-hosts`). See
  [Notifications](notifications.md).
- **SPARQL Update `LOAD` / `SERVICE`** — blocked unless the target host is in
  `lws.sparql-update.allowed-hosts` (empty by default ⇒ blocked entirely). See the
  [SPARQL endpoint](sparql-endpoint.md) page.
- **JSON-LD remote contexts** — refused entirely by default; `lws.jsonld.allowed-context-hosts` may
  permit named vocabulary hosts (https only, size- and time-bounded, no redirects).

> Allow-listing a private host is how an operator deliberately opts into a target the guards would
> otherwise refuse. Keep the allow-lists tight, and prefer deploying where the server cannot reach
> sensitive internal endpoints at all.
{: .warning }

## Resource bounds

`lws.max-request-bytes` (64 MiB default) is enforced from `Content-Length` and again while reading a
chunked body (`413` beyond it). Every JSON body is refused with `400` if nested deeper than 64 levels,
checked before the parser sees it. A linkset's user-managed part is capped by `lws.linkset.max-bytes`.
Subscriptions are limited per subscriber and in lifetime, and anonymous subscriptions are off by
default (`lws.subscriptions.allow-anonymous`).

## Integrity

[RFC 9530](http-api.md) `Content-Digest` is verified on writes that carry it (mismatch ⇒ `400`), and
`Repr-Digest`/`Content-Digest` are served on demand. Only the RFC-recommended `sha-256` / `sha-512`
are produced or verified; the obsolete `md5`/`sha`/`unixsum`/`crc32c` are not. Replacing or patching
a resource requires `If-Match` (`428` otherwise), so lost updates cannot happen. Webhook deliveries
and access-event notifications are signed with [RFC 9421](notifications.md) HTTP Message Signatures;
the `keyid` names the signing key's verification method in the storage description, and the key is
also published at `/.lws/jwks`.

## Quota

`lws.quota.max-bytes` caps total binary-content bytes (`0` = unlimited); over-quota writes get `507`.
RDF graph storage is not metered.

## Keys on disk

The directories that hold private keys — `<data-dir>/keys` (webhook signing seed and the
access-token signing key) and the TLS directory (ACME account and domain keys) — are created
owner-only, and an existing one is tightened to owner-only at startup.

## Caches

The DPoP `jti` replay cache, the OIDC trust/JWKS caches, the SSI-CID subject-document cache and the
WAC agentGroup cache are bounded, TTL-evicting in-process caches (Caffeine). They — and the
stateless-HMAC DPoP nonce secret — are **per-process**; a clustered deployment would need a shared
store. A `jti` entry evicted because the cache is full re-opens a replay window, so size
`lws.dpop.jti-cache-size` above peak load; the server warns when that starts happening. (The search
service's derived type index is likewise in-memory, but it is a complete materialized view rather
than an evictable cache.)

## Things that are client-declared (not attested)

`acl:origin` and the access-grant `purpose` (`LWS-Purpose` header) are **client-declared**, not
cryptographically attested — as is the nature of origin/purpose policy. Treat them as advisory
scoping, not as a security boundary against a hostile client.

## Development-only switches

`lws.dev.open=true` (open mode), `lws.ui.dev-login=true` (UI impersonation, refused off loopback and
behind a proxy) and `lws.sparql.endpoint.read-only=false` exist for development and say so. They
are documented behaviour, not defects — do not enable them on a storage anyone else can reach.

## The embedded SPARQL endpoint bypasses authorization

If enabled, the [embedded Fuseki endpoint](sparql-endpoint.md) operates on the whole dataset and
**bypasses WAC/owner authorization**, exposing internal administrative graphs. It is disabled by
default, and when enabled is query-only and loopback-bound unless reconfigured. Treat it as a trusted
endpoint.
