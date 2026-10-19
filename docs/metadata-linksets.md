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

- **Server-managed links** — `up` (parent container), `linkset` (self) and
  `https://www.w3.org/ns/lws#storage` (the storage URI) — generated on every read. A client
  **cannot** set or override these, with one exception: changing `up` asks the server to
  [move the resource](#moving-a-resource) to another container, which it either does or refuses —
  it is never silently ignored.
- **`type`** is shared: the server always emits the structural type (`lws:Container` /
  `lws:DataResource`) first, and a client may *add* its own types — e.g. declare that a document is a
  `schema:Person`, which is how a binary resource gets a type at all. Nothing in the LWS namespace and
  none of the LDP interaction models may be declared; those name what a resource is to the server.
  Declared types also appear as `Link: rel="type"` on the resource and in container listings, and
  are what [Type Search](search-type-index.md) matches.
- **User-managed links** — any other relations a client sets, persisted in a dedicated metadata graph
  and removed automatically when the resource is deleted.

```json
{
  "linkset": [
    {
      "anchor": "https://storage.example/alice/personalinfo.json",
      "type":        [ { "href": "https://www.w3.org/ns/lws#DataResource" },
                       { "href": "https://schema.org/Person" } ],
      "up":          [ { "href": "https://storage.example/alice/" } ],
      "https://www.w3.org/ns/lws#storage": [ { "href": "https://storage.example/" } ],
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

The user-managed portion is updated with `application/json-patch+json`
([RFC 6902](https://www.rfc-editor.org/rfc/rfc6902)), the patch format lws10-core requires since
w3c/lws-protocol#255, or `application/merge-patch+json`
([RFC 7396](https://www.rfc-editor.org/rfc/rfc7396)), or replaced wholesale with `PUT` of an
`application/linkset+json` document. `Accept-Patch` lists JSON Patch first.

A JSON Patch addresses the document a `GET` returns, whose one link context object, `/linkset/0`, is
the resource's own: `[{"op": "add", "path": "/linkset/0/license", "value": [{"href": "…"}]}]` adds a
license and `remove` takes it away. What the patch leaves must still be a linkset document for the
resource (otherwise `422`); its relations become the user-managed links, and server-managed ones are
ignored. A patch whose pointers address the relations directly (`/license`) is applied to the stored
relation map instead, as it always was. These writes are **conditional**: a missing `If-Match` is refused
with `428`, a stale one with `412`. A JSON Patch whose `test` operation fails or whose JSON Pointer is
unresolvable yields `409`.

A merge patch may be written in either of two shapes, which mean the same thing: the relation map
(`{"license": [{"href": "…"}]}`), or the `application/linkset+json` document a `GET` returns
(`{"linkset": [{"anchor": "…/doc", "license": [{"href": "…"}]}]}`), so a client can patch back what it
read. In the document form every entry's `anchor` must be the resource itself (otherwise `422`), and its
relations merge one at a time like the map's: a relation left out is left alone and `null` removes one.
Server-managed relations are ignored in both.

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

## Moving a resource

The drafts of 19 October 2026 let a client move a resource to another container by changing the `up`
link in its linkset. The storage description says whether that is allowed, and for what, with a
`MoveResource` capability:

```json
{ "type": "MoveResource", "appliesTo": ["DataResource", "Container"], "preservesIdentifier": false }
```

`appliesTo` is `lws.move.applies-to` (both by default; `DataResource` alone, or `none`, which removes
the capability and refuses every `up` change with `409`). `preservesIdentifier` is `false` because
this server's paths follow the containment hierarchy: the moved resource becomes
`<destination><its name>`, or another free name if that one is taken.

```bash
# read the linkset and its ETag, then replace the up link's target (conditionally, as every linkset write)
curl -si http://localhost:8080/notes/list.txt.meta
curl -i -X PATCH http://localhost:8080/notes/list.txt.meta \
     -H 'Content-Type: application/json-patch+json' -H 'If-Match: "<etag>"' \
     --data '[{"op":"test","path":"/linkset/0/up/0/href","value":"http://localhost:8080/notes/"},
              {"op":"replace","path":"/linkset/0/up/0/href","value":"http://localhost:8080/archive/"}]'
```

A move answers `200 OK` with the updated linkset (its `anchor` the new IRI), its new `ETag`, and
`Content-Location` naming the new linkset. A merge patch or a `PUT` of the linkset whose `up` names
another container moves the resource too; a `PUT` that leaves `up` out keeps it, and an `up` that names
the container the resource is already in is no move at all (`204`, as any linkset write).

- **What moves.** The resource and, for a container, everything in it — content, linkset metadata
  and ACL — in one transaction with the rest of the write. Both containers' `items` and `ETag`s change.
  IRIs in a moved ACL that name a moved resource or its ACL are rewritten to follow it; RDF content is
  not rebased (its triples keep their IRIs).
- **Who may.** The agent needs delete permission on the resource (for a container, on everything it
  holds, as a recursive `DELETE` would) and create permission in the destination, besides the write
  permission any linkset write needs. A move is never partly applied.
- **What is refused** (`409`): no `up` left, two `up` targets, an `up` on the storage root, a
  destination that is a data resource or belongs to another storage, a container into itself or one
  of its descendants, a resource type `lws.move.applies-to` leaves out. A destination that does not
  exist is refused as a create there would be. A malformed `up` is `422`.
- **The old IRI.** `GET`/`HEAD` of the previous IRI — or of its `.meta` or `.acl` — answers
  `301 Moved Permanently` to the new one, for a client that may read the resource there; anyone else
  gets exactly what they got before, so the redirect reveals nothing. A resource created later at the
  old IRI takes its place.
- **Notifications.** One `Move` activity (`origin` the container left, `target` the one joined) for
  subscribers who may read the resource where it went; a `Delete` of the old IRI for those who could
  read it only where it was. See [Notifications](notifications.md).
- **Not followed.** Access grants and subscriptions that name the old IRI are left as they are.

## PATCH formats at a glance

| Target | `application/sparql-update` | `application/merge-patch+json` | `application/json-patch+json` |
|---|:--:|:--:|:--:|
| RDF resource | ✓ | — | — |
| JSON (non-RDF) resource | — | ✓ | ✓ |
| Linkset (`.meta`) | — | ✓ | ✓ |

JSON Merge Patch is not accepted on RDF resources — it is not defined over RDF — so SPARQL Update is
the RDF patch format (an update that names a graph is refused with `400`: a resource is a single
graph). The storage description's `PatchSupport` capability lists these pairs per `format`. N3 Patch
(`text/n3`) is intentionally not implemented — the spec does not require it.
