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

A resource's types are its **structural** LWS type (`lws:Container` / `lws:DataResource`) plus any
`rdf:type` its own representation asserts about itself (the resource IRI or a hash fragment of it).

## Type index

`GET /.lws/type-index` lists the distinct types visible to the client:

```json
{ "@context": "https://www.w3.org/ns/lws/v1", "type": "TypeIndex", "totalItems": 5,
  "items": [ { "id": "https://schema.org/Person" }, { "id": "https://schema.org/Event" } ] }
```

## Type search

Equivalent `GET` and `POST` forms carry a **conjunctive-normal-form** filter and return a synthetic
`ContainerPage`. In the `GET` form a comma-separated value is **OR** and a repeated parameter is
**AND**; in the `POST` body a nested array is **OR** and the outer array is **AND**:

```
GET /.lws/type-search?type=https://schema.org/Person,http://xmlns.com/foaf/0.1/Person&type=https://www.w3.org/ns/lws%23DataResource
```

```json
POST /.lws/type-search    Content-Type: application/lws+json
{ "@context": "https://www.w3.org/ns/lws/v1",
  "type": [ ["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"],
            "https://www.w3.org/ns/lws#DataResource" ] }
```

Both select `(schema:Person OR foaf:Person) AND lws:DataResource`.

Beyond the mandatory `type` baseline, a filter key that is an **absolute-URI predicate** matches a
descriptive relation read from the resource's representation (e.g.
`&https%3A%2F%2Fex.org%2Fshape=…`); a relation the server does not index simply yields no matches
(never an error).

### Errors

| Status | Cause |
|---|---|
| `415` | `POST` body that is not `application/lws+json`. |
| `400` | A malformed filter, a non-absolute-URI value, or an over-complex filter. |
| `404` | A page past the last. |
| `405` | An unsupported method. |

## The derived index

Types are served from an **in-memory derived index**, built lazily on first use and maintained
incrementally from resource events (create/update/delete); relation targets are not cached and are
queried on demand for the predicates a search needs.

Per [lws10-searchindex](https://w3c.github.io/lws-protocol/lws10-searchindex/), type/relation
membership may be eventually consistent — though synchronous event delivery makes it read-your-writes
in practice. **Authorization is never cached:** it is applied live, per request, over the index, so a
revoked grant takes effect immediately, and `totalItems` reflects only the requesting client's
authorized view. Descriptive-relation filtering is limited to relations expressed as absolute-URI
predicates in the resource's own representation; structural/protocol relations are never indexed.

Set `lws.search-index.enabled=false` to stop advertising and serving these services.
