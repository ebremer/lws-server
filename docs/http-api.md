---
title: HTTP API
nav_order: 5
---

# HTTP API
{: .no_toc }

1. TOC
{:toc}

## Methods

| Method | Target | Behaviour |
|---|---|---|
| `GET` / `HEAD` | data resource | Content-negotiated representation (Turtle, JSON-LD, N-Triples, RDF/XML); binary streamed as-is, with byte-range support (`206`/`416`, `Accept-Ranges: bytes`). |
| `GET` / `HEAD` | `/` (the storage URI) | The [storage description](#discovery--the-storage-description) (`application/lws+cid`), unless the client asks for a container representation — `application/lws+json`, `application/ld+json`, `application/json` or an RDF type — in which case the root container listing below. |
| `GET` / `HEAD` | container | `application/lws+json` listing (`id`/`type`/`totalItems`/`items[]`, each with `id`/`type`/`format`/`size`/`modified`, `type` naming any declared types after `DataResource`/`Container`); content-negotiable as `application/ld+json` / `application/json` (the requested `Content-Type` is echoed) or RDF; paginated (`?page=N`, `Link` rel `first`/`prev`/`next`/`last`) above `lws.container.page-size`. |
| `POST` | a container | Create a contained resource; `Slug` names it, `Link: rel="type"` picks container/RDF/non-RDF; `201` + `Location`. A [reserved name](#reserved-names) is refused with `409`. |
| `PUT` | any IRI | Create (new) or replace (existing) at that exact IRI; replacing MUST be conditional. The parent container must already exist (`404` otherwise; `409` if the parent is not a container). A reserved path is refused with `409`; an existing container with `409` (its representation is its membership); a `Link: rel="type"` that contradicts the IRI's own shape with `400`. |
| `PATCH` | RDF or JSON resource | RDF: `application/sparql-update` only (JSON Merge Patch is not defined over RDF and is not accepted there); JSON & linkset: `application/merge-patch+json` (RFC 7386) or `application/json-patch+json` (RFC 6902). See [Metadata & Linksets](metadata-linksets.md). |
| `DELETE` | any resource | Delete (non-empty container → `409`, or recursive with `Depth: infinity`); removes the resource's metadata too. |
| `GET`/`HEAD`/`PATCH`/`PUT`/`OPTIONS` | `<resource>.meta` | The resource's linkset (metadata) resource — see [Metadata & Linksets](metadata-linksets.md). |
| `OPTIONS` | any | `Allow`, `Accept-Post`, `Accept-Patch`, `Want-Content-Digest`. |
| `POST` | `<system-prefix>/token` | OAuth 2.0 Token Exchange (RFC 8693) at the embedded authorization server — see [Authentication](authentication.md). |
| `GET` | `/.well-known/lws-configuration` | The embedded authorization server's metadata (RFC 8414). |
| `QUERY` | `<system-prefix>/type-search` | Type Search — see [Search & Type Index](search-type-index.md). |

The interaction model in `Link: rel="type"` may be given as `https://www.w3.org/ns/lws#Container`
or the LDP terms (`ldp:Container`/`ldp:BasicContainer`, `ldp:RDFSource`, `ldp:NonRDFSource`); a
trailing slash on the IRI or `Slug` also makes a container.

<a id="reserved-names"></a>
### Reserved names

Several namespaces belong to the server, and no resource may be created or replaced in them —
`POST` with such a `Slug`, and `PUT` at such a path, are answered `409 Conflict`:

| Reserved | Owned by |
|---|---|
| any name ending `.acl` | the access-control resource of its target |
| any name ending `.meta` | the linkset (metadata) resource of its target |
| `lws.system-prefix` (default `/.lws`) and below | the storage description, JWKS, token endpoint, subscriptions, type index/search, access requests/grants |
| `/app` and `/callback` and below | the management console and the OIDC login callback |
| `/.well-known/lws-configuration` and `/.well-known/acme-challenge` and below | the authorization server metadata and the ACME HTTP-01 responder |

The match ignores case and covers the container form (`.acl/`); the name is tested exactly as sent,
with no percent-decoding, so `x%2Eacl` is a distinct and legal name.

## Response headers & conditional requests

Responses carry `ETag`, `Last-Modified`, and `Link` relations: `rel="type"` — the interaction
models, `https://www.w3.org/ns/lws#Container`/`#DataResource`, and any type the resource's metadata
declares —, `rel="https://www.w3.org/ns/lws#storage"` to the storage URI (on every `GET` and `HEAD`
of a storage resource, linksets, ACLs and the server's own containers included), `rel="up"` (parent
container, non-root), and `rel="linkset"` (the metadata resource); WAC adds `rel="acl"`.

- `If-None-Match` / `If-Modified-Since` → `304 Not Modified`.
- `If-Match` (stale) → `412 Precondition Failed`. A precondition against a resource that does not
  exist is never satisfied — including `If-Match: *` — so such a `PUT` gets `412` rather than
  creating the resource; an unconditional `PUT` still creates.
- An **unconditional PUT replacing an existing resource** is refused with `428 Precondition Required`
  (you must send `If-Match`).
- A write exceeding `lws.quota.max-bytes` → `507 Insufficient Storage`.

`If-Match` is a compare-and-swap: the tag is compared inside the transaction that makes the change,
so of two clients that both read `"v1"` and both `PUT` with `If-Match: "v1"`, exactly one gets `204`
and the other `412`. The same holds for `PATCH`, `DELETE` and linkset writes.

A container's `ETag` changes whenever its membership does, so `GET` a container and `If-Match` that
tag on a write to it. A numbered page (`?page=N`) carries its own tag, which deliberately does *not*
satisfy an `If-Match` on the container; for a paginated container take the tag from the RDF rendering
(`Accept: text/turtle`), which is the full listing and never paginated. Container listings are
filtered per client and sent `Cache-Control: private, no-store`.

A write that cannot be carried out is refused rather than partly performed: a `PUT`/`POST` creating
or replacing a **container** with a body is `409`; a **SPARQL Update that names a graph** (`GRAPH`,
`WITH`, `USING`, graph management) is `400`; a request body carrying RDF outside the default graph
(TriG `GRAPH` blocks, JSON-LD named graphs) is `400`. Deleting a resource removes its content, ACL and
linkset in one transaction.

Non-RDF resources keep their stored media type but are served defensively: every one carries
`X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`, and anything a browser would
execute in this origin (`text/html`, `image/svg+xml`, `application/xhtml+xml`, XML) also gets
`Content-Disposition: attachment`.

## Content negotiation

RDF resources are served in Turtle, JSON-LD, N-Triples, RDF/XML or TriG by `Accept`; the default is
Turtle. Container listings default to `application/lws+json` and also satisfy `application/ld+json`
and `application/json` (the requested type is echoed), or any RDF serialisation.

## Errors

Errors are returned as `application/problem+json` ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)).
A `401` carries the lws10-core challenge — `WWW-Authenticate: Bearer as_uri="<authorization
server>", realm="<storage URI>"` (and the same for `DPoP`, with its `algs`) — and the
`rel="https://www.w3.org/ns/lws#storage"` `Link`, so a client learns where to get an access token and
what to ask for without a hardcoded URI:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer as_uri="https://storage.example", realm="https://storage.example/"
WWW-Authenticate: DPoP as_uri="https://storage.example", realm="https://storage.example/", algs="ES256 ES384 ES512 EdDSA RS256 RS384 RS512 PS256 PS384 PS512"
Link: <https://storage.example/>; rel="https://www.w3.org/ns/lws#storage"
```

## Discovery — the storage description

The storage description is a W3C controlled identifier (CID) document (lws10-core, Storage
Description Resource), served as `application/lws+cid` at the **storage URI** — the server's root,
`/` — and at `<system-prefix>/storage-description` (default `/.lws/storage-description`). At `/`,
`Accept` decides: `application/lws+cid` (or no preference) gets the description, a container type
(`application/lws+json`, `application/ld+json`, `application/json`, RDF) gets the root container.
`application/ld+json`, `application/json` and RDF renderings of the description itself are available
by content negotiation at `/.lws/storage-description`.

Its `@context` is `["https://www.w3.org/ns/cid/v1", "https://www.w3.org/ns/lws/v1"]` and its `id` is
the storage URI.

- The **`service`** array advertises the endpoints on the storage: `StorageRoot` (the root
  container), the `NotificationService`, the `TypeIndexService` / `TypeSearchService`, the
  `AccessRequestService` / `AccessGrantService`, and — when enabled — the
  [embedded SPARQL endpoint](sparql-endpoint.md). Each carries a `type` and a `serviceEndpoint`.
- **`verificationMethod`** publishes the webhook signing key as a `JsonWebKey`, referenced from
  `authentication` — the key a webhook receiver checks [notification signatures](notifications.md)
  against.
- The **`capability`** array uses **structured objects** (`{ type, … }`): the implemented
  specifications (type only; which authentication suites appear depends on configuration); a
  `PatchSupport` entry mapping each target `format` to its accepted PATCH formats; one
  `ContentNegotiation` entry per RDF serialisation (`source` → `target` list); and an RFC 9530
  digest entry listing the supported algorithms.

```jsonc
{
  "@context": ["https://www.w3.org/ns/cid/v1", "https://www.w3.org/ns/lws/v1"],
  "id": "https://storage.example/",
  "type": "Storage",
  "verificationMethod": [
    { "id": "https://storage.example/#iMd12Qh…", "type": "JsonWebKey",
      "controller": "https://storage.example/",
      "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": "iMd12Qh…", "x": "…" } }
  ],
  "authentication": ["https://storage.example/#iMd12Qh…"],
  "capability": [
    { "type": "https://w3c.github.io/lws-protocol/lws10-core/" },
    { "type": "https://w3c.github.io/lws-protocol/lws10-index/" },
    { "type": "https://www.w3.org/ns/lws#PatchSupport",
      "format": { "text/turtle": ["application/sparql-update"],
                  "application/json": ["application/merge-patch+json", "application/json-patch+json"] } },
    { "type": "https://www.w3.org/ns/lws#ContentNegotiation",
      "source": "text/turtle", "target": ["application/ld+json", "application/n-triples", "application/rdf+xml", "application/trig"] },
    { "type": "https://www.rfc-editor.org/info/rfc9530", "algorithm": ["sha-256", "sha-512"] }
  ],
  "service": [
    { "type": "StorageRoot", "serviceEndpoint": "https://storage.example/" },
    { "type": "NotificationService", "serviceEndpoint": "https://storage.example/.lws/subscriptions",
      "subscriptionType": ["WebhookSubscription"] },
    { "type": "TypeIndexService", "serviceEndpoint": "https://storage.example/.lws/type-index" },
    { "type": "TypeSearchService", "serviceEndpoint": "https://storage.example/.lws/type-search" },
    { "type": "AccessRequestService", "serviceEndpoint": "https://storage.example/.lws/access-requests",
      "conformsTo": ["https://www.w3.org/ns/lws#AccessProfile"] },
    { "type": "AccessGrantService", "serviceEndpoint": "https://storage.example/.lws/access-grants",
      "conformsTo": ["https://www.w3.org/ns/lws#AccessProfile"] }
  ]
}
```

## Integrity — RFC 9530 digest fields

The server supports [RFC 9530](https://www.rfc-editor.org/info/rfc9530/) `Content-Digest` /
`Repr-Digest` for `sha-256` and `sha-512`:

- A request that carries a **`Content-Digest`** has its body verified before any write — a mismatch or
  a malformed field is rejected with `400`; digest algorithms the server does not support are ignored.
- Reads honour **`Want-Repr-Digest`** / **`Want-Content-Digest`** by emitting the corresponding
  `Repr-Digest` / `Content-Digest` (highest-weight preference; ties favour the stronger algorithm).
- Non-RDF resources serve a `Repr-Digest` computed from a SHA-256 persisted at write time, so the blob
  is never re-read; `Content-Digest` is omitted on partial `206` range responses (it would not
  describe the bytes actually sent).
- The server advertises that it accepts integrity-protected writes by emitting `Want-Content-Digest`
  on `OPTIONS` and on write responses, and lists digest support as a capability above.

## Examples

```bash
# create an RDF resource in the root container
curl -i -X POST -H 'Content-Type: text/turtle' -H 'Slug: greeting' \
     --data '<#it> <http://schema.org/name> "Hello LWS" .' http://localhost:8080/

# read it back as JSON-LD
curl -H 'Accept: application/ld+json' http://localhost:8080/greeting

# create a container, then a resource in it with PUT, then patch it (SPARQL Update)
curl -X PUT -H 'Link: <https://www.w3.org/ns/lws#Container>; rel="type"' http://localhost:8080/box/
curl -X PUT -H 'Content-Type: text/turtle' --data '<#x> <http://schema.org/n> 1 .' http://localhost:8080/box/x
curl -X PATCH -H 'Content-Type: application/sparql-update' \
     --data 'INSERT DATA { <http://localhost:8080/box/x#x> <http://schema.org/age> 42 }' http://localhost:8080/box/x

# create a JSON resource, then partially update it with JSON Merge Patch (RFC 7386)
curl -X POST -H 'Content-Type: application/json' -H 'Slug: doc.json' \
     --data '{"a":1,"b":2}' http://localhost:8080/
curl -X PATCH -H 'Content-Type: application/merge-patch+json' \
     --data '{"b":null,"c":3}' http://localhost:8080/doc.json   # => {"a":1,"c":3}

# replacing an existing resource needs If-Match (428 without it)
ETAG=$(curl -s -o /dev/null -w '%header{etag}' http://localhost:8080/doc.json)
curl -X PUT -H "If-Match: $ETAG" -H 'Content-Type: application/json' --data '{"a":2}' http://localhost:8080/doc.json

# ask for a representation digest on read
curl -i -H 'Want-Repr-Digest: sha-256=1' http://localhost:8080/greeting
```
