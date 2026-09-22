# LWS Protocol Compliance: lws-server

**Date:** 2026-09-22
**Specification baseline:** the LWS editor's drafts of **21 September 2026** — `w3c/lws-protocol` @
[`3ddc642`](https://github.com/w3c/lws-protocol/commit/3ddc642) ("Clarify DID support in the SSI-CID
authentication suite", #233).
**Previous baseline:** the drafts this server was built against between June and August 2026, which
predate most of the changes listed below. That revision of this document (2026-07-09) is in git
history.
**Related:** `README.md` (behaviour), `TODO.md` drafts band **D** (the work this baseline took),
`REVIEW.md` / `REVIEW-lws-server.md` (security and correctness findings).

## Short answer

`lws-server` implements the **LWS 1.0 editor's drafts of 21 September 2026**: LWS Core — including
the OAuth 2.0 authorization baseline, the controlled-identifier storage description, the notification
data model and access requests and grants —, the vocabulary, the Type Index and QUERY-based Type
Search services, the webhook notification suite, and the three current authentication suites. The
discontinued self-signed `did:key` suite is still accepted, deprecated. Where the server departs from
a draft it does so deliberately, and each departure is listed under
[Deliberate divergences](#deliberate-divergences) with its reason.

The drafts are not a Recommendation: several sections are still marked TBD or "needs to align", the
LWS JSON-LD context is not yet published, and the Core Editor's Draft still carries editorial
scaffolding. Conformance here is to the text as it stands at the baseline commit.

## Specification status

| Specification | Status at the baseline | This server |
|---|---|---|
| [lws10-core](https://w3c.github.io/lws-protocol/lws10-core/) | Editor's Draft, 21 Sep 2026 | Implemented; see below |
| [lws10-vocab](https://w3c.github.io/lws-protocol/lws10-vocab/) | Draft (DNOTE snapshot 14 Jul 2026, vocabulary 21 Sep 2026) | Terms used as defined, `StorageResource` included |
| [lws10-index](https://w3c.github.io/lws-protocol/lws10-index/) (was `lws10-searchindex`) | Draft, renamed 21 Sep 2026 | Implemented, `QUERY` search |
| [lws10-notifications-webhook](https://w3c.github.io/lws-protocol/lws10-notifications-webhook/) | Draft (split from `lws10-notifications`, 24 Jul 2026) | Implemented |
| [lws10-authn-openid](https://w3c.github.io/lws-protocol/lws10-authn-openid/) | Draft | Implemented, at the token endpoint and directly |
| [lws10-authn-saml](https://w3c.github.io/lws-protocol/lws10-authn-saml/) | Draft | Implemented when an IdP certificate is configured |
| [lws10-authn-ssi-cid](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/) | Draft; DID subjects since 21 Sep 2026 | Implemented, with `did:key` and `did:web` subjects |
| [lws10-authn-ssi-did-key](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/) | **Discontinued** 18 Sep 2026 | Credentials without a `kid` still accepted, deprecated; not advertised |

## What changed since the previous baseline

Each spec change after the server's first commit (14 June 2026) that bears on a storage server, and
what the server does about it now.

| Spec change | What it requires | Now |
|---|---|---|
| Authorization (Dec 2025, #45; clarified 18 Jun, #169) | OAuth 2.0 baseline: a storage server validates access tokens from a trusted authorization server; a `401` carries `as_uri` and `realm`; the AS publishes metadata at `/.well-known/lws-configuration` and supports token exchange | **Implemented** — it predates the server but had not been: an embedded authorization server (token exchange, RFC 9068 tokens, metadata, JWKS), access-token validation for it and for trusted external servers, and the challenge. Direct credential presentation kept as an additional mechanism |
| #179 (20 Jul) — `QUERY` replaces `GET`/`POST` search | Type Search is an HTTP `QUERY` (RFC 10008) with an `application/lws-query+json` body; `Accept-Query`; `400`/`415`/`406`/`422`/`404` | **Implemented**; the old `GET`/`POST` forms removed |
| #185 (24 Jul) — notification data model in core | `Notification` envelope with `storage` and `activity`; array `type`s; `target`/`origin`; `application/lws+json` requests, responses and deliveries | **Implemented** |
| #183 (27 Jul) — storage description as a CID document | `application/lws+cid`; `@context` `[cid/v1, lws/v1]`; `id` the storage URI; a mandatory `StorageRoot` service; `rel="…lws#storage"` on every `GET`/`HEAD`; the storage URI answers with the description | **Implemented** — the storage URI is the root container's (see divergence 1) |
| #190 (3 Aug) — conneg consolidated into the media type section | `lws+json`, `ld+json`, `json` equivalent for containers, `Content-Type` echoed, `Vary: Accept` | Already so |
| #187, #203, #199, #218 (3–21 Aug) — context, ACL references, access-request terms | Editorial / terminology | No behaviour change |
| #221 (10 Aug) — `subject_token_types_supported` | AS metadata member | **Implemented** |
| #224 (21 Aug) — `Slug` no longer mentioned | The identity hint is abstract | `Slug` still honoured as the hint |
| #219 (21 Aug) — Activity Streams terms replaced | `mediaType` → `format` (container items and the access-profile operand); `totalItems`/`items` LWS terms; `dcterms:modified` | **Implemented**; the `mediaType` operand still read in stored grants |
| #228 (14 Sep) — ETag requirements | `ETag` on `GET`/`HEAD` of resources and linksets (RFC 9110) | Already so |
| #229 (18 Sep) — did:key suite discontinued | The SSI-CID suite subsumes it | did:key subjects validated by SSI-CID; kid-less did:key credentials accepted, deprecated; capability dropped |
| #234 (21 Sep) — `lws:StorageResource` | The class, and the access-target matcher that matches any Storage Resource | **Implemented** — target matchers are now enforced (they were ignored) |
| #244 (21 Sep) — CID context in the webhook snippet | The signing key is a `verificationMethod` of the storage description, referenced from `authentication`; `keyid` is its id | **Implemented** |
| #249 (21 Sep) — `lws10-index` | Rename | Capability URL updated |
| #227 (21 Sep) — `subject_identifier_types_supported` | AS metadata member | **Implemented**: `https`, `did:key`, `did:web` |
| #233 (21 Sep) — SSI-CID supports DID URIs | DID documents are CID documents | **Implemented** for `did:key` (local) and `did:web` (HTTPS) |

## LWS Core

### Authentication

- **Credential data model.** Every suite yields a subject, issuer and client; a credential must be
  signed (`alg: none` is refused everywhere) and, for the JWT suites, audience-bound
  (`lws.audience`, and at the token endpoint the authorization server itself).
- **Token type identifiers.** `urn:ietf:params:oauth:token-type:id_token` (OpenID),
  `…:jwt` (self-signed CID), `…:saml2` (SAML), as the token endpoint's `subject_token_type`.

### Authorization

| Requirement | Implementation |
|---|---|
| `401` with a conforming challenge: `as_uri`, `realm` | `Bearer as_uri="<issuer>", realm="<storage URI>"` (and `DPoP`, with `algs`); `error` when a token was refused |
| `Link rel="…lws#storage"` on a `401` (SHOULD) | Yes |
| AS metadata at `/.well-known/lws-configuration` (RFC 8414) | Embedded AS; `subject_token_types_supported`, `subject_identifier_types_supported` |
| Token endpoint supports token exchange; `resource` required and must name a known storage; `subject_token` validated | `<system-prefix>/token`; any `resource` other than this storage is `invalid_target` |
| Access token per RFC 9068 with `sub`, `iss`, `client_id`, `aud` (the resource), `exp` (≤ 300 s recommended), `iat`, `jti` | `ES256`, `typ: at+jwt`, 300 s by default, never longer than the credential; DPoP binding (`cnf.jkt`) on request |
| Error responses per RFC 6749 §5.2 | JSON `error`/`error_description`, `Cache-Control: no-store` |
| Storage validates signature (keys from `jwks_uri`, cached, rotation), issuer, audience (exactly one value), `exp`/`nbf`/`iat` | `AccessTokenValidator`; external issuers via their `/.well-known/lws-configuration` |
| Presentation with `Authorization: Bearer` (RFC 6750) | Yes, and `DPoP` (RFC 9449) |

### Discovery

| Requirement | Implementation |
|---|---|
| Storage description is a CID document: `id` the storage URI, `type` `Storage`, `service` with a `StorageRoot`, optional `capability` | Yes |
| `application/lws+cid`; `@context` starting `cid/v1`, `lws/v1` | Yes; `ld+json`, `json` and RDF by negotiation |
| Every `GET`/`HEAD` of a Storage Resource links `rel="…lws#storage"` to the storage | Resources, linksets, ACLs, the subscription and access containers |
| Requests for the storage URI return the description | Yes — `/`, unless a container representation is asked for (divergence 1) |

### Containers, operations and metadata

| Requirement | Implementation |
|---|---|
| Container representation: `id`, `type`, `totalItems`, `items`; items with `id`, `type`, `format` (MUST for data resources), `size`, `modified` | Yes; item `type` also names declared types |
| `lws+json` / `ld+json` / `json` equivalence, `Content-Type` echoed, `Vary: Accept` | Yes |
| Pagination: `first` MUST, `next` when more, opaque links, `200` | Yes (`?page=N`) |
| Create with `POST`; `Link: <…lws#Container>; rel="type"` for a container; `201` + `Location`; `up`, `linkset` (with `type`), `type` links | Yes |
| Read: range requests, `ETag`, `Link`s, `HEAD` | Yes |
| Update: `PUT`/`PATCH`; merge patch MUST be supported | JSON resources and linksets: yes. RDF resources: refused (divergence 2) |
| `Prefer: set-linkset` | Yes |
| Delete: `204`; non-empty container `409` unless `Depth: infinity` | Yes, atomically with its linkset and ACL |
| Linkset: `application/linkset+json`, `Allow` includes `GET`, `PATCH`; `Accept-Patch: application/merge-patch+json`; `412` on a failed precondition | Yes (`PUT` and JSON Patch as well) |
| Types in `Link` headers, including user-defined ones | Yes — the types a client declares with `Link: rel="type"` are advertised on `GET`/`HEAD` |
| `PreferLinkRelations` | `Prefer: include="…"`/`omit="…"` on a linkset read (divergence 7) |

### Notifications (core data model)

| Requirement | Implementation |
|---|---|
| `NotificationService` with `serviceEndpoint` and `subscriptionType` | Yes |
| Envelope: `type` `Notification`, `storage`, `activity` | Yes, `@context` `[lws/v1, activitystreams]` |
| Activity: `id`, `type` (array), `object` (`id`, `type` array), `published` (RFC 3339); `target` on `Create`, `origin` on `Delete`; `actor` optional | Yes; `actor` omitted unless `lws.notifications.include-actor` (the privacy SHOULD) |
| Subscription request `application/lws+json` with `type` and `topic` | Yes |
| Response `application/lws+json` with `type` and `subscription` | Yes (`201`, `Location`, `expires`) |
| Authorization at subscription and at delivery time; revocation stops delivery | Yes, including for deletes (decided before the delete) |

### Access requests and grants

| Requirement | Implementation |
|---|---|
| `AccessRequestService` / `AccessGrantService` with `conformsTo` `lws#AccessProfile` | Yes |
| Endpoints are LWS containers: `GET`, `POST` (`Location`), `DELETE` | Yes; listings are paginated container representations of data resources |
| `type`, `storage` (URI), `inbox`, `access` | Yes; `storage` must be this storage |
| Access profile: `AccessPolicy`; actions `read`/`modify`/`create`/`delete`; `assignee` (or `foaf:Agent`); `target` with a matcher `type` (`StorageResource`, `DataResource`, `Container`) and `value`s | Yes; matchers enforced, unknown ones refused |
| Constraints `client`, `format`, `type`, `purpose`, `dateTime`; all must hold | Yes, fail-closed; `mediaType` read as `format` in stored grants |
| Notifications on request and grant creation, in the notification data model | Yes |
| Privacy: hide a client-constrained grant from other clients | Yes |

## Vocabulary

The server writes the terms the vocabulary defines, as it defines them: `format` is `dcterms:format`,
`modified` `dcterms:modified`, `size` `schema:size`, `inbox` `ldp:inbox`, `expires` `schema:expires`,
`items`/`totalItems` in the LWS namespace, and the storage description's `service`,
`serviceEndpoint`, `verificationMethod`, `authentication` and `controller` in the CID context's
namespaces in its RDF rendering.

## Type Index and Type Search (lws10-index)

| Requirement | Implementation |
|---|---|
| `TypeIndexService` / `TypeSearchService` advertised | Yes |
| Type index: `GET`, paginated `TypeIndex` of the client's visible types | Yes |
| Type search: `QUERY` with `application/lws-query+json`; `Content-Type` required (`400`); other formats `415` with `Accept-Query`; `OPTIONS` with `Allow` and `Accept-Query` | Yes |
| Filter: `@`-members ignored; `type` optional; CNF; empty group `400`; empty value no constraint; duplicates ignored; relation keys; absolute-IRI values (`400`) | Yes; `{}` matches everything visible |
| Over-complex filter `422`, never narrowed | Yes (32 groups / 256 values) |
| `406` when `Accept` excludes the result formats; `Vary: Accept` | Yes |
| `ContainerPage` items with `id` and `type` | Yes |
| Stale page link `404`/`410` | `404` |
| Types from `Link` headers, server state and content, treated identically | Yes |
| Indexed relations not enumerated; unindexed ≡ unmatched; structural relations never indexed | Yes |
| Authorization filtering live; counts over the filtered view; not shared-cacheable | Yes; `Cache-Control: private, no-store`, `Vary: Authorization` |

## Webhook notification suite

| Requirement | Implementation |
|---|---|
| `WebhookSubscription` with `inbox` and `expires` | Yes |
| Subscription management: `GET` lists as an LWS container (paging SHOULD); `GET`/`DELETE` a subscription | Yes |
| Delivery body `application/lws+json` | Yes |
| RFC 9421 signature over `@method @scheme @authority @path content-type content-digest`, `created` and `keyid` | Yes |
| Signing key in the storage description as a `verificationMethod` referenced from `authentication`; `keyid` its id | Yes: `<storage URI>#<thumbprint>`, `JsonWebKey` |

## Authentication suites

| Suite | Implementation |
|---|---|
| **OpenID Connect** | ID token, not `none`; `sub`/`iss`/`azp`; subject document read as a CID document (JSON first — the suite's own example is plain JSON — or RDF) whose own `service` names `iss` as `lws#OpenIdProvider`; OIDC discovery for the key |
| **SAML 2.0** | Out-of-band trust; one assertion, one enveloped signature bound to it; `NameID`/`Issuer`/`Recipient`/`Audience` |
| **Self-signed CID** | `sub` = `iss` = `client_id`; `exp` and `iat` required; `kid` selects a method of the `authentication` relationship (CID 1.0 §3.3): controlled by the subject, in its document, `JsonWebKey` (no private members) or `Multikey`, not revoked or expired. Subjects: HTTPS, `did:key` (local), `did:web` (HTTPS) |
| **did:key** (discontinued) | Credentials without a `kid` still accepted, deprecated |

## Deliberate divergences

| # | Divergence | Why |
|---|---|---|
| 1 | **The storage URI is the root container's URI** | lws10-core allows it ("Storage MAY function as a root container"), and the alternatives are worse: the `realm` must logically contain every resource, so it cannot be a URI no resource starts with, and moving the root would move every resource. `/` therefore answers with the description unless a container representation is requested. A generic `Accept: application/json` gets the listing, since the core makes `json` a container type; a webhook receiver should ask for `application/lws+cid` |
| 2 | **Merge patch is refused on RDF resources (`415`)** | lws10-core: a server "MUST minimally support JSON Merge Patch". Applying it through the JSON-LD form of a graph destroyed multi-subject graphs (finding H21); SPARQL Update is the RDF patch format. Merge patch works on JSON resources and linksets |
| 3 | **Replacing or patching requires `If-Match` (`428` otherwise)** — resources and linksets | Stricter than the SHOULD; it is what makes lost updates impossible rather than unlikely |
| 4 | **Authentication credentials are accepted directly by default** | An additional mechanism lws10-core permits, and how every existing client of this server authenticates. `lws.oauth.accept-authentication-credentials=false` turns it off |
| 5 | **kid-less did:key credentials are accepted** | The discontinued suite's credentials; the SSI-CID suite requires a `kid`. Deprecated, not advertised |
| 6 | **`JsonWebKey2020` and `Ed25519VerificationKey2020` read as `JsonWebKey` and `Multikey`** | Same key material in the same members, and common in existing DID documents |
| 7 | **`PreferLinkRelations` wire syntax** | The core names the preference but not its syntax; `Prefer: include="…"` / `omit="…"` is this server's |
| 8 | **An access-grant `target` is required** | The profile makes it OPTIONAL; a grant without one would authorize nothing or everything, so it is refused |
| 9 | **The LWS JSON-LD context is referenced, never fetched** | `https://www.w3.org/ns/lws/v1` is not published yet (its digest is a TODO in the core); documents name it and the RDF renderings use this server's mapping. The CID v1 context is bundled |
| 10 | **The authorization server is minimal** | Token exchange only, public clients, one key, tokens for this storage only; the core leaves the rest to OAuth |
| 11 | **`subject_identifier_types_supported` lists `"https"`** | The prose says values start with a scheme such as `"https:"`, the example and the default say `"https"`; the example is followed |

## Open items

- **OpenID EdDSA ID tokens** cannot be verified, and the algorithm allow-list is seeded from the
  token's own header (a `TODO.md` low-tail item, not a spec change).
- **DID methods** other than `did:key` and `did:web` are refused by name; no universal resolver is
  consulted.
- The access-request notification section is marked "needs to align" in the core; the server
  delivers the core notification data model there.
