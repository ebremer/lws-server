# LWS Protocol Compliance: lws-server

**Date:** 2026-09-22; **last re-reviewed 2026-10-19** against the specifications as they stood on
**19 October 2026** (`w3c/lws-protocol` @ [`9a08ff6`](https://github.com/w3c/lws-protocol/commit/9a08ff6)),
the text of the core Working Draft W3C published that day. Three of its changes are normative for a
storage server and each needed code: RFC 9728 protected resource metadata for discovery (#256), the
LWS profile in content negotiation (#253) and moving resources between containers (#237); see
[Re-review of 19 October 2026](#re-review-of-19-october-2026).
**Specification baseline:** the LWS drafts of **19 October 2026** — `w3c/lws-protocol` @
[`9a08ff6`](https://github.com/w3c/lws-protocol/commit/9a08ff6) ("Define how resources move between
containers", #237). Before it, the drafts of 5 October 2026 (`ef02548`, #255) and of 21 September 2026
(`3ddc642`, #233), whose changes the table
[What changed since the previous baseline](#what-changed-since-the-previous-baseline) lists.
**Previous baseline:** the drafts this server was built against between June and August 2026, which
predate most of the changes listed below. That revision of this document (2026-07-09) is in git
history.
**Related:** `README.md` (behaviour), `TODO.md` drafts band **D** (the work each baseline took),
`REVIEW.md` / `REVIEW-lws-server.md` (security and correctness findings).

## Short answer

`lws-server` implements the **LWS 1.0 drafts of 19 October 2026**: LWS Core — including
the OAuth 2.0 authorization baseline with RFC 9728 discovery, the controlled-identifier storage
description, the LWS profile, moving resources between containers, the notification data model and
access requests and grants —, the vocabulary, the Type Index and QUERY-based Type
Search services, the webhook notification suite, and the three current authentication suites. The
discontinued self-signed `did:key` suite is still accepted, deprecated. Where the server departs from
a draft it does so deliberately, and each departure is listed under
[Deliberate divergences](#deliberate-divergences) with its reason.

The drafts are not a Recommendation: several sections are still marked TBD or "needs to align" (and
protected resource metadata is marked at risk), the LWS JSON-LD context is not yet published at its
URL, and the Core Editor's Draft still carries editorial scaffolding. Conformance here is to the text as it stands at the baseline commit.

## Specification status

| Specification | Status at the baseline | Latest on w3.org/TR, 19 Oct 2026 | This server |
|---|---|---|---|
| [lws10-core](https://w3c.github.io/lws-protocol/lws10-core/) | Editor's Draft, 19 Oct 2026 | Working Draft **19 Oct 2026** — the baseline text | Implemented; see below |
| [lws10-vocab](https://w3c.github.io/lws-protocol/lws10-vocab/) | Draft (vocabulary 19 Oct 2026: `MoveResource`, `appliesTo`, `preservesIdentifier`, `as:Move`) | Group Note Draft 14 Jul 2026 (predates `StorageResource` and the move terms) | Terms used as defined; the context the Working Group builds from it is bundled (divergence 9) |
| [lws10-index](https://w3c.github.io/lws-protocol/lws10-index/) (was `lws10-searchindex`) | Draft, renamed 21 Sep 2026 | not published (editor's draft only) | Implemented, `QUERY` search |
| [lws10-notifications-webhook](https://w3c.github.io/lws-protocol/lws10-notifications-webhook/) | Draft (split from `lws10-notifications`, 24 Jul 2026) | not published (editor's draft only) | Implemented |
| [lws10-authn-openid](https://w3c.github.io/lws-protocol/lws10-authn-openid/) | Draft | Working Draft **15 Oct 2026** (wording only since 3 Aug) | Implemented, at the token endpoint and directly |
| [lws10-authn-saml](https://w3c.github.io/lws-protocol/lws10-authn-saml/) | Draft | Working Draft **15 Oct 2026** (wording and the example's XML only since 3 Aug) | Implemented when an IdP certificate is configured |
| [lws10-authn-ssi-cid](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/) | Draft; DID subjects since 21 Sep 2026 | Working Draft **15 Oct 2026** (wording only since 21 Sep) | Implemented, with `did:key` and `did:web` subjects |
| [lws10-authn-ssi-did-key](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/) | **Discontinued** 18 Sep 2026 | Working Draft 3 Aug 2026; published as a **Discontinued Draft on 29 Sep 2026** | Credentials without a `kid` still accepted, deprecated; not advertised |

## Re-review of 19 October 2026

Re-checked on 2026-10-19 against `w3c/lws-protocol` `main` at `9a08ff6`, the text of the core Working
Draft W3C published that day (`WD-lws10-core-20261019`), and the authentication suites' Working Drafts
of 15 October. Touchstone run `3c0421aa` (Touchstone's D-0100 baseline, the same day) found the three
normative changes before any code moved: 13 MUST failures, every one of them one of these.

| Commit | Change | Effect here |
|---|---|---|
| #256 (RFC 9728) | A `401`'s conforming challenge MUST carry `resource_metadata`, the URL of the **protected resource metadata** of the requested resource (RFC 9728), and the response MUST link to the storage (`rel="…lws#storage"`, a SHOULD before). The metadata MUST name at least one authorization server (`authorization_servers`), and its `resource` is the URL requested. `as_uri` and `realm` are gone. The token request's `resource` MUST be the storage the `Link` names, the token's `aud` MUST include it, and a storage now checks that `aud` *includes* its URI (it was "exactly one value"). Clients check that the metadata URL and the storage root are on the origin they asked and that `resource` is the URL they asked | Every challenge (`Bearer`, `DPoP`, `SAML2`, a DPoP nonce challenge and every refused token) carries `resource_metadata` first. The new endpoint `/.well-known/oauth-protected-resource<path>` answers for any path, stored or not, without authentication: `resource` the URL requested character for character, `authorization_servers` the embedded issuer then `lws.oauth.trusted-issuers`, plus `bearer_methods_supported` and the DPoP members RFC 9728 defines. `as_uri` and `realm` still follow `resource_metadata` for clients of the earlier drafts (the draft allows other parameters) unless `lws.oauth.legacy-challenge=false`. An access token whose `aud` includes the storage among other values is accepted; the embedded server still issues exactly one. Token exchange already required the storage URI as `resource` |
| #253 | Only `application/lws+json` MUST be honoured on a container; `ld+json` and `json` are no longer its equivalents. The URI `https://www.w3.org/ns/lws/v1` identifies the **LWS profile**: a client names it in the `profile` parameter of an RDF media type, and the server then MUST answer RDF isomorphic to the `lws+json` representation of the same container state and page, naming the profile in `Content-Type`, or not select that type | A container's RDF is now the `lws+json` document of the same page read as JSON-LD, so it is isomorphic by construction, and paginated, tagged and conditional exactly as the JSON is. It was the whole membership, unpaginated, with statements the JSON does not make (`lws:storage`, the container's `dcterms:modified`) and without the members' format, size and modified time, so Touchstone's `container-lws-profile-*` tests failed. Turtle, N-Triples, RDF/XML, TriG and (new, for containers) N-Quads; `ld+json` with the profile gets the `lws+json` body. The profile is echoed in `Content-Type` when asked for; a range naming another profile matches nothing. The subscription list and the access request and grant endpoints negotiate the same way; the type index and type search are not containers and never claim the profile. `ld+json` and `json` are still served. The context is bundled (divergence 9) |
| #237 | A client **moves** a resource by changing the `up` link in its linkset with JSON Patch. A storage that allows it MUST describe a `MoveResource` capability (`appliesTo`, default data resources only; `preservesIdentifier`), and one that does not MUST refuse the change. The destination must be an existing container; a move is atomic, needs delete on the resource (recursively for a container) and create in the destination, refuses cycles, and keeps content and user metadata. A storage that does not preserve the identifier answers `200` with the updated linkset and `Content-Location`, and SHOULD answer the previous identifiers with `301`. A move is announced as one `Move` activity with `origin` and `target` | Implemented; see [Moving resources](#moving-resources). Identifiers here are derived from the containment hierarchy, so the capability says `preservesIdentifier: false` (divergence 13) and applies to data resources and containers by default (`lws.move.applies-to`, divergence 12). An `up` change used to be dropped as a server-managed link and answered `204` with nothing moved, which Touchstone's `move-refused-without-capability` caught |
| #264, #275, #269, #270, #271, #273 | Wording, examples and the SAML example's XML | None |
| #265, #268, #274 | Vocabulary: specification links, URI terminology, the move terms and `AccessRequest` | The move terms are used as defined |

## Re-review of 5 October 2026

Re-checked on 2026-10-05 against `w3c/lws-protocol` `main` at `ef02548`, the text of the core Working
Draft W3C published that day (`WD-lws10-core-20261005`). The other Working Drafts on w3.org/TR, and
`lws-contrib/lws-test-suite` (still `b8cb134`), had not changed.

| Commit | Change | Effect here |
|---|---|---|
| #255 (5 Oct) | Servers MUST support and advertise **JSON Patch** (RFC 6902, `application/json-patch+json`) as the baseline patch format, for `PATCH` on resources and on linksets, replacing JSON Merge Patch and its citation of RFC 7386 (which RFC 7396 obsoletes). The storage description example lists JSON Patch first; merge patch stays an optional alternative | JSON Patch was already accepted and advertised, on JSON resources and linksets. On a linkset, though, it was applied to the relation map the links are stored as, so a patch of the document a `GET` returns (`/linkset/0/license`) answered `409`; Touchstone run `4d7187f2` found it (`linkset-patch-json-patch`, and the `describedby` type-search tests). Such a patch is now applied to the document, its result checked as a linkset document for the resource (`422` otherwise); a patch addressing the relations directly still applies to the map. `Accept-Patch` and `PatchSupport` list JSON Patch first. Refused on RDF resources, as merge patch is (divergence 2) |

## Re-review of 28 September 2026

Re-checked on 2026-09-30 against `w3c/lws-protocol` `main` at `9b03b32` (28 September 2026), the
Working Drafts then on w3.org/TR, and the W3C namespace documents.

**Nothing normative changed.** Four commits landed after the baseline, and none touches a
specification's normative text:

| Commit | Change | Effect here |
|---|---|---|
| #251, #252 (23 Sep) | The discontinued `did:key` suite's Discontinued Draft snapshot, dated 29 September: styling, and a note saying the SSI-CID suite subsumes it | None; divergence 5 stands |
| #213 (25 Sep) | The README links the [LWS 1.0 test suite](https://github.com/lws-contrib/lws-test-suite) | None; see below |
| #248 (28 Sep) | Wiki notes on the HTTP `QUERY` method (RFC 10008) | None; Type Search already uses `QUERY` |

The Working Drafts of Core and the SSI-CID suite published on 21 September were built from `2b130c2`
and `3ddc642`. Nothing under `lws10-core/` differs between those two commits, so what is published is
the baseline text. The LWS JSON-LD context (`https://www.w3.org/ns/lws/v1`) still answers `404`, so
divergence 9 stands.

**The test suite cannot be used to check conformance yet.** `lws-contrib/lws-test-suite` is at
`b8cb134` (20 September). As committed, several of its manifests have broken references and cannot
be loaded. Its tests also encode the pre-core drafts: a `storageDescription` link, the description as
`lws+json`, `200` from `DELETE`, and the `id_token` type for `did:key`. A server that follows the
Working Draft fails those tests. Once the suite follows the Working Draft, running it here is the
next conformance check.

**Open upstream pull requests.** These are not part of the specifications as of 28 September.
They are listed here because each would change what a storage server does:

| PR | Proposes | This server today |
|---|---|---|
| #255 | JSON Patch (RFC 6902) replaces JSON Merge Patch as the baseline `PATCH` format, for resources and linksets | **Merged 5 October**; see [Re-review of 5 October 2026](#re-review-of-5-october-2026). The answer recorded here, that linksets already took it, held only for patches written against the stored relations |
| #253 | The LWS container shape is required only for `application/lws+json`, no longer for plain `ld+json`/`json` | **Merged 19 October**, with the LWS profile; see [Re-review of 19 October 2026](#re-review-of-19-october-2026) |
| #241 | Create into a missing container: `404` explicitly, with no intermediate containers | Already the case |
| #237 | Moving a resource by `PATCH`ing its `up` link | **Merged 19 October**; implemented, see [Moving resources](#moving-resources) |
| #162 | WebSocket and Server-Sent Events notification channels | Not implemented |

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
| #255 (5 Oct) — JSON Patch the baseline | `application/json-patch+json` on resources and linksets, advertised first | **Implemented**; on a linkset it addresses the document a `GET` returns |
| #256 (19 Oct) — RFC 9728 for discovery | `resource_metadata` in place of `as_uri`/`realm`; protected resource metadata naming the authorization servers; the token's `resource` and `aud` are the storage the `401` links to; `aud` *includes* the storage | **Implemented**; `as_uri`/`realm` still sent too unless `lws.oauth.legacy-challenge=false` |
| #253 (19 Oct) — the LWS profile | Only `lws+json` required on containers; RDF in the profile isomorphic to it, the profile in `Content-Type` | **Implemented**; container RDF derived from the `lws+json` page |
| #237 (19 Oct) — moving resources | `MoveResource`; an `up` change moves the resource or is refused; atomic, authorized as delete + create; `Move` activity | **Implemented**, `preservesIdentifier: false` |

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
| `401` with a conforming challenge: `resource_metadata` (RFC 9728 §5.1), the metadata URL of the resource requested | `Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource<base path><path>[?query]"` (and `DPoP`, with `algs`, and `SAML2` when SAML is configured); then `as_uri`/`realm` for clients of earlier drafts unless `lws.oauth.legacy-challenge=false`; `error` when a token was refused |
| `Link rel="…lws#storage"` on a `401` (MUST since #256) | Yes |
| Protected resource metadata (RFC 9728) with `resource` and at least one `authorization_servers` entry | `/.well-known/oauth-protected-resource<path>`, the same document for every path, no authentication: `resource` the URL requested, `authorization_servers` the embedded issuer then the trusted ones, `bearer_methods_supported`, `dpop_signing_alg_values_supported`, `dpop_bound_access_tokens_required`. `404`, and no `resource_metadata`, on a storage that names no authorization server (configuration warns) |
| AS metadata at `/.well-known/lws-configuration` (RFC 8414) | Embedded AS; `subject_token_types_supported`, `subject_identifier_types_supported` |
| Token endpoint supports token exchange; `resource` required: the storage the `401` linked to; `subject_token` validated | `<system-prefix>/token`; any `resource` other than this storage is `invalid_target` |
| Access token per RFC 9068 with `sub`, `iss`, `client_id`, `aud` (the resource), `exp` (≤ 300 s recommended), `iat`, `jti` | `ES256`, `typ: at+jwt`, 300 s by default, never longer than the credential; DPoP binding (`cnf.jkt`) on request |
| Error responses per RFC 6749 §5.2 | JSON `error`/`error_description`, `Cache-Control: no-store` |
| Storage validates signature (keys from `jwks_uri`, cached, rotation), issuer, audience (includes the storage URI; "exactly one value" before #256), `exp`/`nbf`/`iat` | `AccessTokenValidator`; external issuers via their `/.well-known/lws-configuration` |
| Presentation with `Authorization: Bearer` (RFC 6750) | Yes, and `DPoP` (RFC 9449) |

### Discovery

| Requirement | Implementation |
|---|---|
| Storage description is a CID document: `id` the storage URI, `type` `Storage`, `service` with a `StorageRoot`, optional `capability` | Yes |
| `application/lws+cid`; `@context` starting `cid/v1`, `lws/v1` | Yes; `ld+json`, `json` and RDF by negotiation |
| Every `GET`/`HEAD` of a Storage Resource links `rel="…lws#storage"` to the storage | Resources, linksets, ACLs, the subscription and access containers |
| Requests for the storage URI return the description | Yes — `/`, unless a container representation is asked for (divergence 1) |
| A storage that lets clients change the `up` link describes a `MoveResource` capability (`appliesTo`, `preservesIdentifier`) | `{"type": "MoveResource", "appliesTo": [<lws.move.applies-to>], "preservesIdentifier": false}`, in every rendering; none when moving is off |

### Containers, operations and metadata

| Requirement | Implementation |
|---|---|
| Container representation: `id`, `type`, `totalItems`, `items`; items with `id`, `type`, `format` (MUST for data resources), `size`, `modified` | Yes; item `type` also names declared types |
| `application/lws+json` honoured; `Content-Type` the selected media type; `Vary: Accept` | Yes; `ld+json` and `json` still served with the same body |
| LWS profile: an RDF media type with `profile="https://www.w3.org/ns/lws/v1"` is answered RDF isomorphic to the `lws+json` of the same state and page, with the profile in `Content-Type` | Yes: Turtle, N-Triples, RDF/XML, TriG, N-Quads and `ld+json`, derived from the `lws+json` page with the bundled context; a range naming another profile matches nothing |
| Pagination: `first` MUST, `next` when more, opaque links, `200` | Yes (`?page=N`) |
| Create with `POST`; `Link: <…lws#Container>; rel="type"` for a container; `201` + `Location`; `up`, `linkset` (with `type`), `type` links | Yes |
| Read: range requests, `ETag`, `Link`s, `HEAD` | Yes |
| Update: `PUT`/`PATCH`; JSON Patch MUST be supported (#255; JSON Merge Patch before it) | JSON resources and linksets: yes, and merge patch as well. RDF resources: refused (divergence 2) |
| `Prefer: set-linkset` | Yes |
| Delete: `204`; non-empty container `409` unless `Depth: infinity` | Yes, atomically with its linkset and ACL |
| Linkset: `application/linkset+json`, `Allow` includes `GET`, `PATCH`; `Accept-Patch: application/json-patch+json`; `412` on a failed precondition | Yes; a JSON Patch addresses the document a `GET` returns (`PUT` and merge patch as well) |
| Types in `Link` headers, including user-defined ones | Yes — the types a client declares with `Link: rel="type"` are advertised on `GET`/`HEAD` |
| `PreferLinkRelations` | `Prefer: include="…"`/`omit="…"` on a linkset read (divergence 7) |
| Links a client may not modify are preserved by a patch; an `up` change without `MoveResource` is refused (4xx) | Yes: `409` when moving is off, or for a type `lws.move.applies-to` leaves out |

### Moving resources

| Requirement | Implementation |
|---|---|
| A move is a partial update of the linkset replacing the `up` target; JSON Patch MUST be supported; conditional SHOULD (`428` MAY) | JSON Patch on the document (`/linkset/0/up/0/href`), merge patch and `PUT` of the linkset too; `If-Match` required (divergence 3). The requested `up` is read from what the write leaves, hrefs resolved against the linkset URL; the same container is no move (`204`) |
| Destination an existing container; no `up` left refused; another storage MAY be refused | `409` for no `up`, two `up` targets, the root, a data resource, another storage; an absent destination is refused as a create there would be (`404`, or `401`/`403` per authorization) |
| Atomic: removed from the old container's `items`, added to the new one's; both ETags change | One transaction with the `If-Match` compare and the rest of the write; both containers touched |
| Content, user metadata and non-modifiable links preserved; auxiliary resources stay bound | The registry entry, an RDF source's content graph, the linkset metadata and the ACL of the resource and every descendant move with it; ACL IRIs naming a moved resource or its ACL are rewritten to follow it. RDF content is not rebased: its triples keep their IRIs |
| No cycles: a container cannot move into itself or a descendant | `409`, with the draft's problem title |
| Authorization: delete on the resource (recursive for a container, the whole subtree, never partially) and create in the destination | Yes, plus the write permission every linkset write needs; warmed before the transaction, decided inside it |
| Identifier: SHOULD be preserved; if not, `200` with the updated linkset (`anchor` the new identifier) and `Content-Location` of the new linkset; previous identifiers SHOULD answer `301` with the same access control | Not preserved (divergence 13): `<destination><name>`, another name if that one is taken. `200`, `application/linkset+json`, `Content-Location`, `ETag`. `GET`/`HEAD` of a previous identifier, or of its `.meta` or `.acl`, answers `301` to the new one for a caller who may read it, and what it answered before to anyone else |
| Moving containers: `Container` in `appliesTo`; descendants move with it; refused otherwise | Yes, by default; `lws.move.applies-to=DataResource` refuses container moves with `409` |
| A single `Move` activity, `origin` and `target` | One per move; subscribers who may read the new location get `Move`, those who could read only the old one a `Delete` of the old IRI, nobody else anything |

### Notifications (core data model)

| Requirement | Implementation |
|---|---|
| `NotificationService` with `serviceEndpoint` and `subscriptionType` | Yes |
| Envelope: `type` `Notification`, `storage`, `activity` | Yes, `@context` `[lws/v1, activitystreams]` |
| Activity: `id`, `type` (array), `object` (`id`, `type` array), `published` (RFC 3339); `target` on `Create`, `origin` on `Delete`, both on `Move`; `actor` optional | Yes; `actor` omitted unless `lws.notifications.include-actor` (the privacy SHOULD) |
| `Move` supported by a storage that moves resources | Yes; `object` is the resource after the move |
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
namespaces in its RDF rendering. The move terms of 19 October are used as defined: a `MoveResource`
capability with `appliesTo` (strings) and `preservesIdentifier` (`xsd:boolean` in RDF), and the
Activity Streams `Move` activity.

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
| 1 | **The storage URI is the root container's URI** | lws10-core allows it ("Storage MAY function as a root container"), and the alternatives are worse: the storage URI is the audience of every access token and the target of every storage link, a URI no resource starts with would sit outside the hierarchy it names, and moving the root would move every resource. `/` therefore answers with the description unless a container representation is requested. A generic `Accept: application/json` gets the listing, since the core makes `json` a container type; a webhook receiver should ask for `application/lws+cid` |
| 2 | **JSON Patch and merge patch are refused on RDF resources (`415`)** | lws10-core: a server "MUST minimally support JSON Patch" (JSON Merge Patch before #255). Applying either through the JSON-LD form of a graph is unsound: merge patch destroyed multi-subject graphs (finding H21), and the JSON-LD shape is no stable pointer target. SPARQL Update is the RDF patch format. Both JSON formats work on JSON resources and linksets |
| 3 | **Replacing or patching requires `If-Match` (`428` otherwise)** — resources and linksets | Stricter than the SHOULD; it is what makes lost updates impossible rather than unlikely |
| 4 | **Authentication credentials are accepted directly by default** | An additional mechanism lws10-core permits, and how every existing client of this server authenticates. `lws.oauth.accept-authentication-credentials=false` turns it off |
| 5 | **kid-less did:key credentials are accepted** | The discontinued suite's credentials; the SSI-CID suite requires a `kid`. Deprecated, not advertised |
| 6 | **`JsonWebKey2020` and `Ed25519VerificationKey2020` read as `JsonWebKey` and `Multikey`** | Same key material in the same members, and common in existing DID documents |
| 7 | **`PreferLinkRelations` wire syntax** | The core names the preference but not its syntax; `Prefer: include="…"` / `omit="…"` is this server's |
| 8 | **An access-grant `target` is required** | The profile makes it OPTIONAL; a grant without one would authorize nothing or everything, so it is refused |
| 9 | **The LWS JSON-LD context is bundled, never fetched** | `https://www.w3.org/ns/lws/v1` still answers `404` (its digest is a TODO in the core). The server carries the context the Working Group's CI builds from `lws10-vocab/vocabulary.yml` (`contexts/lws-v1.jsonld`, published at `w3c.github.io/lws-protocol/lws10-vocab/vocabulary.context.jsonld` after `9a08ff6`, unmodified, sha256 `b2dda589…`), the copy Touchstone reads `lws+json` with; container RDF in the LWS profile is derived through it. The storage description's RDF rendering is still this server's own mapping. The CID v1 context is bundled too |
| 10 | **The authorization server is minimal** | Token exchange only, public clients, one key, tokens for this storage only; the core leaves the rest to OAuth |
| 11 | **`subject_identifier_types_supported` lists `"https"`** | The prose says values start with a scheme such as `"https:"`, the example and the default say `"https"`; the example is followed |
| 12 | **Moving is on by default, for containers too** | The core says servers SHOULD describe `MoveResource` only where their deployment requires it and restrict `appliesTo` to what they need. This server's deployments exist to exercise the protocol, so `lws.move.applies-to` defaults to `DataResource,Container`; set it to `DataResource` or `none` where moves are not wanted |
| 13 | **A moved resource gets a new identifier (`preservesIdentifier: false`)** | Servers SHOULD preserve it. Here a resource's path is its container's path plus its name, and paths drive WAC inheritance, the type index and every IRI the server mints, so a resource whose IRI no longer said where it is would be governed by the wrong ACLs. The capability says so, the `200` reports the new identifier, and the old one answers `301` |

## Open items

- **OpenID EdDSA ID tokens** cannot be verified, and the algorithm allow-list is seeded from the
  token's own header (a `TODO.md` low-tail item, not a spec change).
- **DID methods** other than `did:key` and `did:web` are refused by name; no universal resolver is
  consulted.
- The access-request notification section is marked "needs to align" in the core; the server
  delivers the core notification data model there.
- **After a move**, access grants whose targets name a previous identifier, and subscriptions whose
  topics do, are left as they are: they name identifiers, and the core notes that a move can change
  who may access a resource. The RDF content of a moved RDF source is not rebased, so triples about
  its old IRI (`<#it>` parsed against it) keep that IRI.
- **Protected resource metadata is at risk** in the core draft ("the Working Group is actively seeking
  implementer feedback"); `as_uri`/`realm` stay in the challenge, after `resource_metadata`, until
  that settles (`lws.oauth.legacy-challenge`).
