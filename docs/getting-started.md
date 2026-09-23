---
title: Getting Started
nav_order: 2
---

# Getting Started
{: .no_toc }

1. TOC
{:toc}

## Prerequisites

- **JDK 21+** (built and tested on JDK 25).
- **Maven 3.9+**.

## Build

```bash
mvn -DskipTests package
```

This produces an executable `target/lws-server.jar`.

## Run

### Spring Boot (default)

```bash
java -jar target/lws-server.jar
# or
mvn spring-boot:run
```

### Bare Eclipse Jetty (no Spring)

The same servlets and filters run on a hand-built Jetty server with no Spring on the classpath — the
intended future deployment target, and the only path that can [terminate TLS itself](deployment.md).

```bash
mvn dependency:build-classpath -Dmdep.outputFile=target/cp.txt
java -cp "target/classes:$(cat target/cp.txt)" com.ebremer.lws.server.JettyLauncher
```

The server listens on the port in `lws.base-uri` (default `http://localhost:8080`).

## First requests

```bash
# create an RDF resource in the root container
curl -i -X POST -H 'Content-Type: text/turtle' -H 'Slug: greeting' \
     --data '<#it> <http://schema.org/name> "Hello LWS" .' http://localhost:8080/

# read it back as JSON-LD
curl -H 'Accept: application/ld+json' http://localhost:8080/greeting

# create a container, add a resource, then patch it with SPARQL Update
curl -X PUT -H 'Link: <http://www.w3.org/ns/ldp#Container>; rel="type"' http://localhost:8080/box/
curl -X PUT -H 'Content-Type: text/turtle' --data '<#x> <http://schema.org/n> 1 .' http://localhost:8080/box/x
curl -X PATCH -H 'Content-Type: application/sparql-update' \
     --data 'INSERT DATA { <http://localhost:8080/box/x#x> <http://schema.org/age> 42 }' http://localhost:8080/box/x

# discover the storage's capabilities and services
curl http://localhost:8080/.lws/storage-description
```

See the [HTTP API](http-api.md) for the full surface.

## Open mode and the first owner

With **no `lws.owners` configured the server runs in open mode** — all reads and writes are permitted.
That is convenient for local development but must not be used in production. Set one or more owner
identifiers in `lws.owners` to enforce the [authorization](authorization.md) policy.

You need a *credential* for an owner before you can act as one. The self-signed
[`did:key`](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/) suite needs no identity
provider, so a bundled helper can mint the very first owner offline:

```bash
# from the packaged fat jar
java -cp target/lws-server.jar -Dloader.main=com.ebremer.lws.server.tools.DidKeyTool \
     org.springframework.boot.loader.launch.PropertiesLauncher

# or, from a source checkout
mvn -q exec:java -Dexec.mainClass=com.ebremer.lws.server.tools.DidKeyTool
```

It prints:

1. a `did:key:…` to drop into `lws.owners`,
2. a private-key **seed** to keep secret (pass it back with `--key <seed>` to re-mint tokens for the
   same identity), and
3. a ready **Bearer token** to send as `Authorization: Bearer <token>`.

Options: `--ttl <seconds>` (token lifetime, default 3600) and `--audience <aud>`. Put the DID in
`lws.owners`, restart, and the token authenticates you as that owner.

## Next steps

- [Configuration](configuration.md) — tune storage, auth, quotas, TLS.
- [Authentication](authentication.md) — the credential suites and DPoP.
- [Authorization](authorization.md) — owner mode vs Web Access Control, and access grants.
- [Deployment & TLS](deployment.md) — production behind a proxy, or with built-in Let's Encrypt.
