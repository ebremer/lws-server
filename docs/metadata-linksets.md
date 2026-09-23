---
title: Metadata & Linksets
nav_order: 6
---

# Metadata & Linksets
{: .no_toc }

1. TOC
{:toc}

Every resource has a **linkset resource** at `<resource>.meta`
([RFC 9264](https://www.rfc-editor.org/rfc/rfc9264), `application/linkset+json`), discoverable via the
`rel="linkset"` `Link` header on the resource. It is the resource's metadata document.

## Server-managed vs user-managed links

The linkset merges:

- **Server-managed links** — `type`, `up` (parent container), `linkset` (self) and the storage
  description — generated on every read. A client **cannot** set or override these.
- **User-managed links** — any other relations a client sets, persisted in a dedicated metadata graph
  and removed automatically when the resource is deleted.

```json
{
  "linkset": [
    {
      "anchor": "https://storage.example/alice/personalinfo.json",
      "type":        [ { "href": "https://www.w3.org/ns/lws#DataResource" } ],
      "up":          [ { "href": "https://storage.example/alice/" } ],
      "describedby": [ { "href": "https://shapes.example/personal-info" } ],
      "title": "Personal information"
    }
  ]
}
```

## Value shapes — links and literals

A relation's value may be:

- an **RFC 9264 target array** — objects with `href` plus optional link attributes such as `title`
  (`"describedby": [ { "href": "...", "title": "Schema" } ]`); or
- a **literal** — a JSON string or array, e.g. a `title` or `creator` label.

Both round-trip unchanged, so **literal-valued core metadata is supported** even though RFC 9264 is
otherwise href-based.

## Updating the linkset

The user-managed portion is updated with `application/merge-patch+json`
([RFC 7386](https://www.rfc-editor.org/rfc/rfc7386)) or `application/json-patch+json`
([RFC 6902](https://www.rfc-editor.org/rfc/rfc6902)), or replaced wholesale with `PUT` of an
`application/linkset+json` document. These writes are **conditional**: a missing `If-Match` is refused
with `428`, a stale one with `412`. A JSON Patch whose `test` operation fails or whose JSON Pointer is
unresolvable yields `409`.

```bash
# add a user-managed relation (conditional)
ETAG=$(curl -sI http://localhost:8080/doc.meta | grep -i '^etag' | tr -d '\r' | cut -d' ' -f2)
curl -X PATCH -H 'Content-Type: application/merge-patch+json' -H "If-Match: $ETAG" \
     --data '{"describedby":[{"href":"https://shapes.example/S"}]}' \
     http://localhost:8080/doc.meta
```

## Prefer (RFC 7240)

Two [RFC 7240](https://www.rfc-editor.org/rfc/rfc7240) preferences tune metadata writes and reads:

- **`Prefer: set-linkset`** on a resource `PUT`/`PATCH` applies that request's `Link` headers to the
  resource's linkset in the *same* operation — a replacement on `PUT`, a partial update on `PATCH` —
  and echoes `Preference-Applied: set-linkset`. It is off unless the header is sent, so ordinary
  writes never touch metadata.

  ```bash
  curl -X PUT -H 'Content-Type: text/turtle' \
       -H 'Prefer: set-linkset' \
       -H 'Link: <https://shapes.example/S>; rel="describedby"' \
       --data '<#it> <http://schema.org/name> "x" .' http://localhost:8080/doc
  ```

- **`Prefer: include="…"` / `omit="…"`** on a linkset read returns only — or drops — the listed
  relations (the structural `anchor` is always kept), and echoes `Preference-Applied`. This is the
  server's RFC 7240 encoding of the LWS *PreferLinkRelations* preference, whose wire syntax the spec
  leaves open.

  ```bash
  curl -H 'Prefer: include="up describedby"' http://localhost:8080/doc.meta
  ```

## PATCH formats at a glance

| Target | `application/sparql-update` | `application/merge-patch+json` | `application/json-patch+json` |
|---|:--:|:--:|:--:|
| RDF resource | ✓ | ✓ (via JSON-LD) | — |
| JSON (non-RDF) resource | — | ✓ | ✓ |
| Linkset (`.meta`) | — | ✓ | ✓ |

Merge Patch on an RDF resource is applied through its JSON-LD representation, so it is most
predictable on simple/single-node shapes; use SPARQL Update for precise graph edits. N3 Patch
(`text/n3`) is intentionally not implemented — the spec does not require it.
