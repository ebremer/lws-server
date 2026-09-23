---
title: Authentication
nav_order: 7
---

# Authentication
{: .no_toc }

1. TOC
{:toc}

LWS separates *who you are* from *what you may do here*. A client proves its identity with an
**authentication credential** (an OpenID ID token, a self-signed controlled-identifier JWT, or a SAML
assertion), exchanges it at an **authorization server** for an **access token**, and presents the
token to the storage. This server embeds that authorization server, and also accepts credentials
presented directly (see [below](#credentials-presented-directly)).

## Discovering where to authenticate

A request that needs authentication and has none is answered `401` with a challenge naming the
authorization server (`as_uri`) and the protection space (`realm`, the storage URI), plus the
storage's `Link: rel="https://www.w3.org/ns/lws#storage"`:

```bash
curl -si http://localhost:8080/private | grep -i www-authenticate
#   WWW-Authenticate: Bearer as_uri="http://localhost:8080", realm="http://localhost:8080/"
#   WWW-Authenticate: DPoP as_uri="http://localhost:8080", realm="http://localhost:8080/", algs="ES256 …"
```

When a token was presented and refused, the challenge also carries an `error`.

## Access tokens: the embedded authorization server

The embedded authorization server (`lws.oauth.enabled`, on by default) is the LWS Authorization
baseline:

| | |
|---|---|
| Metadata (RFC 8414) | `GET /.well-known/lws-configuration` — `issuer` is the storage's base URI; lists `token_endpoint`, `jwks_uri`, `subject_token_types_supported`, `subject_identifier_types_supported` |
| Token endpoint | `POST <system-prefix>/token` (default `/.lws/token`) — OAuth 2.0 Token Exchange (RFC 8693) |
| Signing key | `ES256` (P-256), kept owner-only at `<data-dir>/keys/oauth-es256.jwk`; published at `/.lws/jwks` |

```bash
curl -s http://localhost:8080/.well-known/lws-configuration        # RFC 8414 metadata
curl -s http://localhost:8080/.lws/token \
     -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     --data-urlencode resource=http://localhost:8080/ \
     --data-urlencode subject_token="$CREDENTIAL" \
     -d subject_token_type=urn:ietf:params:oauth:token-type:jwt
#   {"access_token":"eyJ...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
#    "token_type":"Bearer","expires_in":300}
```

The token endpoint validates the `subject_token` with the suite its `subject_token_type` names:

| `subject_token_type` | Suite |
|---|---|
| `urn:ietf:params:oauth:token-type:id_token` | OpenID Connect |
| `urn:ietf:params:oauth:token-type:jwt` | Self-signed controlled identifier (including `did:key` subjects) |
| `urn:ietf:params:oauth:token-type:saml2` | SAML 2.0 |

The credential's audience must name this authorization server (the storage's base URI) or its token
endpoint. The issued token is an **RFC 9068 JWT** (`typ: at+jwt`, `ES256`) with `iss` this server,
`sub` and `client_id` the credential's subject and client, `aud` exactly the storage URI, and a
lifetime of `lws.oauth.access-token-lifetime-seconds` (default 300 s) that never outlives the
credential. Only this storage is a valid `resource` (anything else is `invalid_target`). Errors
follow RFC 6749 §5.2 (`error` / `error_description`, `Cache-Control: no-store`). A token request
that carries a `DPoP` proof gets a DPoP-bound token (`cnf.jkt`, `token_type: DPoP`).

The storage's `AccessTokenValidator` checks an access token's signature (keys from the issuer's
`jwks_uri`, cached, with rotation), its issuer — the embedded server, or one listed in
`lws.oauth.trusted-issuers`, whose metadata is read from `/.well-known/lws-configuration` inserted
before the issuer's path (RFC 8414 §3.1) — its audience (exactly one value: this storage),
`exp`/`nbf`/`iat`, and requires `sub`, `client_id` and `jti`.

The authorization server is deliberately minimal: token exchange only (no authorization-code flow,
no refresh tokens, no client registration — lws10-core identifies a client by the URI in its
credential), public clients, one signing key, tokens for this storage only. To rotate the key,
delete `keys/oauth-es256.jwk` and restart; outstanding tokens stop validating at most one token
lifetime early.

> Serving the storage under a path (e.g. `https://example.org/lws`) makes that path part of the
> issuer, so RFC 8414 clients look for the metadata at `/.well-known/lws-configuration/lws`. Map
> that address to the server's `/.well-known/lws-configuration` at the reverse proxy — see
> [Deployment](deployment.md).
{: .note }

## Credentials presented directly

A credential may also be sent straight to the storage as `Authorization: Bearer <credential>` (or
`SAML2 <assertion>`) — this server's behaviour before the baseline, and an additional mechanism
lws10-core permits. It stays on unless `lws.oauth.accept-authentication-credentials=false`. A single
orchestrator routes each credential to the right suite by its shape and returns the authenticated
principal, which is carried on the request and read by the [authorization](authorization.md) layer.

## The authentication suites

| Suite | Credential | Verification key comes from |
|---|---|---|
| **OpenID Connect** | signed ID token (`iss` ≠ `sub`) | the issuer's JWKS, via OIDC discovery — trusted because the subject's controlled-identifier document (JSON, as the suite's example writes it, or RDF) links *the subject itself* to an `lws:OpenIdProvider` service whose `serviceEndpoint` equals `iss`. A provider named elsewhere in the document does not count. |
| **Self-signed controlled identifier (SSI-CID)** | self-issued JWT (`sub` = `iss` = `client_id`) with `exp`, `iat` and a `kid`; the subject is an HTTPS URL, a `did:key` or a `did:web` | the verification method the `kid` names among those the subject document's **`authentication`** relationship lists (CID 1.0 §3.3): controlled by the subject, a `JsonWebKey` (no private members) or `Multikey`, not revoked or expired. A `did:key` expands to its DID document locally, with no network lookup; a `did:web` is fetched from its `https://…/did.json`. |
| **did:key** (discontinued) | self-issued JWT whose `did:key` subject names **no** `kid` | the key the identifier encodes. Kept, deprecated and unadvertised, only for credentials minted before the SSI-CID suite subsumed it. |
| **SAML 2.0** | signed SAML assertion (optionally base64) | a pre-configured trusted IdP key (out-of-band trust); the XML signature is validated, bound to the assertion whose claims are read, and `NameID`/`Issuer`/`Recipient` are mapped to subject/issuer/client. |

All JWT suites reject `alg: none` and enforce `exp`. `JsonWebKey2020` and
`Ed25519VerificationKey2020` methods are read as `JsonWebKey` and `Multikey`.

**SAML.** Trust is configured with `lws.saml.idp-certificates` (and optionally
`lws.saml.trusted-issuers` / `lws.saml.audience`); without a certificate the suite is inactive. The
credential is profiled tightly against signature wrapping: exactly one `saml:Assertion` and exactly
one `ds:Signature`, which must be that assertion's own enveloped signature naming it by `ID`, with
every claim read from the assertion's direct children. Setting `lws.saml.audience` makes an
`AudienceRestriction` required, and every restriction present must name this storage.

**Interactive sign-in.** `jakartaee-pac4j` additionally provides optional OIDC sign-in for the
[management UI](management-ui.md) when an OIDC client is configured (`lws.oidc.*`); the console login
applies the same WebID-to-provider check as the API.

## Audience binding

Every JWT credential is checked against `lws.audience`, which defaults to this storage's own IRI. A
token whose `aud` names something else is **always** refused, and — unless
`lws.audience.require=false` — a token with no `aud` at all is refused too. This is what stops a
credential presented here from being replayed against another LWS storage, and stops an ID token
minted for a different relying party of the same provider from authenticating its subject here.

Self-signed credentials (SSI-CID, including `did:key`) are additionally capped at
`lws.token.max-lifetime-seconds` (default 3600), since their holder chooses their own expiry.

## Bootstrapping an owner with did:key

A `did:key` subject needs no identity provider — its DID document is derived from the identifier —
so the bundled `DidKeyTool` can mint the first owner offline:

```bash
java -cp target/lws-server.jar -Dloader.main=com.ebremer.lws.server.tools.DidKeyTool \
     org.springframework.boot.loader.launch.PropertiesLauncher --audience http://localhost:8080
```

It prints a `did:key:…` to put in `lws.owners`, a private-key seed to keep secret (`--key <seed>`
re-mints credentials for the same identity), and a credential whose `kid` names the DID's
verification method, so it is an SSI-CID credential: send it as `Authorization: Bearer <token>`, or
exchange it at `/.lws/token`. Options: `--ttl <seconds>` (default 3600) and `--audience <aud>`.

> **Pass `--audience` with the storage's base URI** (`lws.base-uri`, e.g.
> `https://storage.example/lws`). Without an `aud` the credential is refused both directly and at
> the token endpoint, since `lws.audience.require` defaults to `true`.
{: .warning }

See [Getting Started](getting-started.md) for the full first-run walk-through.

## Proof-of-possession (DPoP, RFC 9449)

Use `Authorization: DPoP <access-token>` together with a `DPoP: <proof-jwt>` header. The server
verifies the proof:

- its `typ` is `dpop+jwt` and the algorithm is not `none`;
- the signature is made by the public key embedded in the proof's `jwk` header;
- `htm` / `htu` match the request method and URL (the `htu` is built from `lws.base-uri`, so it is
  correct behind a [reverse proxy](deployment.md));
- `iat` is fresh;
- the `jti` has not been seen before; and
- `ath` is the SHA-256 of the access token.

It then requires the access token's `cnf.jkt` to equal the proof key's JWK thumbprint — so a stolen
token is useless without the holder's private key. The `jti` is *consumed* (making the proof
single-use) only after the access token has itself validated and been found bound to the proof key,
so an unauthenticated client cannot fill the replay cache.

A DPoP-bound token (one carrying `cnf.jkt`) is **refused** when presented as `Authorization: Bearer`
(RFC 9449 §7.1). Set `lws.dpop.require=true` to refuse plain `Bearer` altogether.

**Server-issued nonces (§8).** Set `lws.dpop.require-nonce=true` to require a server-issued `nonce`
claim in proofs. A nonceless request is answered `401` with a `DPoP-Nonce` header for the client to
retry with. Nonces are stateless (an HMAC over a timestamp under a per-process secret).

The `jti` replay cache is a bounded, TTL-evicting cache sized by `lws.dpop.jti-cache-size`
(default 100 000); an entry evicted because the cache is *full* has not expired, so size it above
your peak DPoP request rate per acceptance window — the server warns when size evictions start. The
cache and the nonce secret are per-process; a clustered deployment would need a shared store. See
[Security](security.md).

## Outbound-fetch SSRF guard

Authentication dereferences URLs taken from **untrusted token claims** — the WebID/CID `sub`, a
`did:web` document, the OIDC issuer `iss` and its JWKS, an external authorization server's metadata
— which is a server-side request forgery (SSRF) surface. An `OutboundFetchPolicy` gates every such
fetch:

- non-`http(s)` schemes are **always** refused (closing `file://` local-file reads), and
- by default hosts resolving to loopback, private, link-local (incl. the cloud-metadata
  `169.254.169.254`), wildcard or multicast addresses are blocked
  (`lws.fetch.block-private-addresses`, with a `lws.fetch.allowed-hosts` exemption for an internal
  IdP).

The document loader follows redirects itself, re-applying the policy to every hop. The same guard
protects [WAC group resolution](authorization.md). See [Security](security.md).

## Example

```bash
# an owner credential from DidKeyTool, exchanged for an access token, then used
AT=$(curl -s http://localhost:8080/.lws/token \
       -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
       --data-urlencode resource=http://localhost:8080/ \
       --data-urlencode subject_token="$CREDENTIAL" \
       -d subject_token_type=urn:ietf:params:oauth:token-type:jwt | jq -r .access_token)
curl -H "Authorization: Bearer $AT" http://localhost:8080/private-resource
```
