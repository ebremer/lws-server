---
title: Search & Type Index
nav_order: 10
---

# Search & Type Index
{: .no_toc }

1. TOC
{:toc}

The [storage description](http-api.md#discovery--the-storage-description) advertises a
`TypeIndexService` and a `TypeSearchService`, each with a `serviceEndpoint`. Both answer
`application/lws+json`, are paginated (`?page=N` with `first`/`prev`/`next`/`last` `Link` relations),
and are **authorization-filtered for the requesting client** — a type or resource the client cannot
read never appears, and `totalItems` counts only that view, so a client cannot discover that a private
type or resource exists. Responses are `Cache-Control: private, no-store`.

A resource's types are its **structural** LWS type (`lws:Container` / `lws:DataResource`), the types
a client declared with `Link: rel="type"` on a write or in its [linkset](metadata-linksets.md)
(lws10-index's preferred source), and any `rdf:type` its own representation asserts about itself (the
resource IRI or a hash fragment of it). All three are treated identically.

## Type index

`GET /.lws/type-index` lists the distinct types visible to the client:

```json
{ "@context": "https://www.w3.org/ns/lws/v1", "type": "TypeIndex", "totalItems": 5,
  "items": [ { "id": "https://schema.org/Person" }, { "id": "https://schema.org/Event" } ] }
```

## Type search

Type Search is an HTTP **`QUERY`** ([RFC 10008](https://www.rfc-editor.org/rfc/rfc10008)) to the
`TypeSearchService` endpoint whose body is an **`application/lws-query+json`** filter in
conjunctive normal form; it returns a synthetic `ContainerPage` whose items carry `id` and `type`.
A nested array is **OR** and the outer array is **AND**:

```json
QUERY /.lws/type-search    Content-Type: application/lws-query+json
{ "type": [ ["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"],
            "https://www.w3.org/ns/lws#DataResource" ] }
```

selects `(schema:Person OR foaf:Person) AND lws:DataResource`.

```bash
curl -X QUERY -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/lws-query+json' \
     --data '{"type":["https://schema.org/Person"]}' http://localhost:8080/.lws/type-search
```

- The filter is plain JSON: an `@`-member is ignored, duplicates are ignored, an empty value is no
  constraint, and every key is optional — `{}` matches every resource the client may read.
- Besides `type`, a key names a **link relation**, with the same grammar: a registered name such as
  `describedby` matches the links the resource's metadata declares, and an absolute-URI key matches
  those and the triples its representation asserts with that predicate. A relation the server does
  not index yields no matches, indistinguishably from a target nothing declares; the server-managed
  relations are never indexed.
- `OPTIONS` answers `Allow: OPTIONS, QUERY` and `Accept-Query: application/lws-query+json`.
- **Page links** (`first`/`prev`/`next`/`last`) are opaque and dereferenced with `GET`: they carry the
  filter (`?q=…&page=N`), not the client's authorization, which is applied again on every page.

The `GET`/`POST` search forms of the drafts before July 2026 are gone.

### Errors

| Status | Cause |
|---|---|
| `400` | A missing `Content-Type`, a malformed filter, an empty OR-group, or a value that is not an absolute IRI. |
| `415` | A query format other than `application/lws-query+json` (the response carries `Accept-Query`). |
| `422` | A filter past the complexity bound (32 groups / 256 values) — never silently narrowed. |
| `406` | An `Accept` that excludes the JSON result formats. |
| `404` | A page link that is past the last page or no longer recognized. |
| `405` | An unsupported method. |

## The derived index

Types are served from an **in-memory derived index**, built lazily on first use and maintained
incrementally from resource events (create/update/delete); relation targets are not cached and are
queried on demand for the predicates a search needs.

Per [lws10-index](https://w3c.github.io/lws-protocol/lws10-index/) (formerly lws10-searchindex), type/relation
membership may be eventually consistent — though synchronous event delivery makes it read-your-writes
in practice. **Authorization is never cached:** it is applied live, per request, over the index, so a
revoked grant takes effect immediately, and `totalItems` reflects only the requesting client's
authorized view (responses also carry `Vary: Authorization`). Structural/protocol relations are
never indexed.

Set `lws.search-index.enabled=false` to stop advertising and serving these services;
`lws.search-index.page-size` (default 100) bounds the items per page.
