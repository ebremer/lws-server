---
title: Authentication
nav_order: 7
---

# Authentication
{: .no_toc }

1. TOC
{:toc}

Present a credential in the `Authorization` header (`Bearer`, `DPoP`, or `SAML2`). A single
orchestrator routes it to the right suite by shape and returns the authenticated principal; Apache
Shiro manages the resulting subject. All four LWS suites are supported.

## The four suites

| Suite | Credential | Verification key comes from |
|---|---|---|
| **OpenID Connect** | signed JWT (`iss` ≠ `sub`) | the issuer's JWKS, via OIDC discovery — trusted because the subject's controlled-identifier document advertises an `lws:OpenIdProvider` service whose `serviceEndpoint` equals `iss`. |
| **SSI Controlled Identifier** | self-issued JWT (`sub` = `iss` = `client_id`, an HTTPS URL) | a `verificationMethod` (`publicKeyJwk`) selected by the JWT `kid` in the dereferenced controlled-identifier document. |
| **did:key** | self-issued JWT (`sub` = `iss` = `client_id`, a `did:key:` URI) | the public key encoded in the `did:key` identifier itself (Ed25519, P-256, secp256k1) — **no network lookup**. |
| **SAML 2.0** | signed SAML assertion (optionally base64) | a pre-configured trusted IdP key (out-of-band trust); the XML signature is validated and `NameID`/`Issuer`/`Recipient` mapped to subject/issuer/client. |

All JWT suites reject `alg: none` and enforce `exp`. SAML trust is configured via
`lws.saml.idp-certificates` (and optionally `lws.saml.trusted-issuers` / `lws.saml.audience`);
without a configured certificate the SAML suite is inactive.

The `did:key` suite needs no identity provider, which makes it ideal for
[bootstrapping the first owner](getting-started.md#open-mode-and-the-first-owner) offline.

`jakartaee-pac4j` additionally provides optional interactive OIDC sign-in for the [management
UI](management-ui.md) when an OIDC client is configured (`lws.oidc.*`).

## Proof-of-possession (DPoP, RFC 9449)

Use `Authorization: DPoP <access-token>` together with a `DPoP: <proof-jwt>` header. The server
verifies the proof:

- its `typ` is `dpop+jwt` and the algorithm is not `none`;
- the signature is made by the public key embedded in the proof's `jwk` header;
- `htm` / `htu` match the request method and URL (the `htu` is built from `lws.base-uri`, so it is
  correct behind a [reverse proxy](deployment.md));
- `iat` is fresh;
- the `jti` is single-use (replay-protected); and
- `ath` is the SHA-256 of the access token.

It then requires the access token's `cnf.jkt` to equal the proof key's JWK thumbprint — so a stolen
token is useless without the holder's private key. Plain `Bearer` tokens skip these checks.

**Server-issued nonces (§8).** Set `lws.dpop.require-nonce=true` to require a server-issued `nonce`
claim in proofs. A nonceless request is answered `401` with a `DPoP-Nonce` header for the client to
retry with. Nonces are stateless (an HMAC over a timestamp under a per-process secret), so there is
no nonce store to maintain.

The `jti` replay cache is a bounded, TTL-evicting cache; the replay cache and nonce secret are
per-process — a clustered deployment would need a shared store. See [Security](security.md).

## Outbound-fetch SSRF guard

Authentication dereferences URLs taken from **untrusted token claims** — the WebID/CID `sub`, the
OIDC issuer `iss`, and the issuer's JWKS — which is a server-side request forgery (SSRF) surface. An
`OutboundFetchPolicy` gates every such fetch:

- non-`http(s)` schemes are **always** refused (closing `file://` local-file reads via the RDF
  loader), and
- by default hosts resolving to loopback, private, link-local (incl. the cloud-metadata
  `169.254.169.254`), wildcard or multicast addresses are blocked
  (`lws.fetch.block-private-addresses`, with a `lws.fetch.allowed-hosts` exemption for an internal
  IdP).

The same guard protects [WAC group resolution](authorization.md). See [Security](security.md) for the
full picture, including the residual redirect caveat.

## Example

```bash
# did:key Bearer token minted by the bundled helper (see Getting Started)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/private-resource
```
