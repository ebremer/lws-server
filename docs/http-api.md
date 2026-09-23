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
| `GET` / `HEAD` | container | `application/lws+json` listing (`id`/`type`/`totalItems`/`items[]`, each with `id`/`type`/`mediaType`/`size`/`modified`); content-negotiable as `application/ld+json` / `application/json` (the requested `Content-Type` is echoed) or RDF; paginated (`?page=N`, `Link` rel `first`/`prev`/`next`/`last`) above `lws.container.page-size`. |
| `POST` | a container | Create a contained resource; `Slug` names it, `Link: rel="type"` picks container/RDF/non-RDF; `201` + `Location`. |
| `PUT` | any IRI | Create (new) or replace (existing) at that exact IRI; replacing MUST be conditional. |
| `PATCH` | RDF or JSON resource | RDF: `application/merge-patch+json` (RFC 7386) or `application/sparql-update`; JSON & linkset: `application/merge-patch+json` or `application/json-patch+json` (RFC 6902). See [Metadata & Linksets](metadata-linksets.md). |
| `DELETE` | any resource | Delete (non-empty container → `409`, or recursive with `Depth: infinity`); removes the resource's metadata too. |
| `GET`/`HEAD`/`PATCH`/`PUT`/`OPTIONS` | `<resource>.meta` | The resource's linkset (metadata) resource — see [Metadata & Linksets](metadata-linksets.md). |
| `OPTIONS` | any | `Allow`, `Accept-Post`, `Accept-Patch`, `Want-Content-Digest`. |

## Response headers & conditional requests

Responses carry `ETag`, `Last-Modified`, and `Link` relations: `rel="type"` interaction models,
`rel="…/lws#storageDescription"`, `rel="up"` (parent container, non-root), and `rel="linkset"`
(the metadata resource); WAC adds `rel="acl"`.

- `If-None-Match` / `If-Modified-Since` → `304 Not Modified`.
- `If-Match` (stale) → `412 Precondition Failed`.
- An **unconditional PUT replacing an existing resource** is refused with `428 Precondition Required`
  (you must send `If-Match`).
- A write exceeding `lws.quota.max-bytes` → `507 Insufficient Storage`.

## Content negotiation

RDF resources are served in Turtle, JSON-LD, N-Triples, RDF/XML or TriG by `Accept`; the default is
Turtle. Container listings default to `application/lws+json` and also satisfy `application/ld+json`
and `application/json` (the requested type is echoed), or any RDF serialisation.

## Errors

Errors are returned as `application/problem+json` ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)).
A `401` carries `WWW-Authenticate` and a `rel="storageDescription"` `Link` so a client can discover
how to authenticate without a hardcoded URI.

## Discovery — the storage description

The storage description is served at `/.lws/storage-description` as `application/lws+json`: the
canonical `{ id, type: "Storage", capability, service }` document. RDF is available via content
negotiation.

- The **`service`** array advertises the endpoints on the storage: `StorageDescription` (itself), the
  `NotificationService`, the `TypeIndexService` / `TypeSearchService`, the `AccessRequestService` /
  `AccessGrantService`, and — when enabled — the [embedded SPARQL endpoint](sparql-endpoint.md). Each
  carries an `rdf:type` and a `serviceEndpoint`.
- The **`capability`** array uses **structured objects** (`{ type, … }`): the implemented protocol
  modules (type only); a `PatchSupport` entry mapping each target media type to its accepted PATCH
  formats; a `ContentNegotiation` entry listing the interchangeable RDF serialisations; and an
  RFC 9530 digest entry listing the supported algorithms.

```jsonc
{
  "@context": "https://www.w3.org/ns/lws/v1",
  "id": "https://storage.example/",
  "type": "Storage",
  "capability": [
    { "type": "https://w3c.github.io/lws-protocol/lws10-core/" },
    { "type": "https://www.w3.org/ns/lws#PatchSupport",
      "mediaType": { "text/turtle": ["application/sparql-update", "application/merge-patch+json"] } },
    { "type": "https://www.rfc-editor.org/info/rfc9530", "algorithm": ["sha-256", "sha-512"] }
  ],
  "service": [
    { "type": "StorageDescription", "serviceEndpoint": "https://storage.example/.lws/storage-description" },
    { "type": "NotificationService", "serviceEndpoint": "https://storage.example/.lws/subscriptions",
      "subscriptionType": ["WebhookSubscription"] }
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

# create a JSON resource, then partially update it with JSON Merge Patch (RFC 7386)
curl -X POST -H 'Content-Type: application/json' -H 'Slug: doc.json' \
     --data '{"a":1,"b":2}' http://localhost:8080/
curl -X PATCH -H 'Content-Type: application/merge-patch+json' \
     --data '{"b":null,"c":3}' http://localhost:8080/doc.json   # => {"a":1,"c":3}

# ask for a representation digest on read
curl -i -H 'Want-Repr-Digest: sha-256=1' http://localhost:8080/greeting
```
