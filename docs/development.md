---
title: Development
nav_order: 15
---

# Development
{: .no_toc }

1. TOC
{:toc}

## Build & test

```bash
mvn package        # compile, run the test suite, build target/lws-server.jar
mvn -DskipTests package
mvn test           # tests only
mvn test -Dtest=LwsConfigurationTest   # one class
```

Requires **JDK 25** (`maven.compiler.release=25`). The full suite is a little over 550 tests and
takes a few minutes. GitHub Actions (`.github/workflows/build.yml`) runs it on every push and pull
request, and weekly on a schedule so a withdrawn or vulnerable dependency is noticed; a change that
touches only `docs/` skips it.

## Project layout

The codebase is intentionally framework-light — see [Architecture](architecture.md). Spring Boot is
only a bootstrapper; the whole object graph is wired by the annotation-free `LwsComponents`, and the
bare-Jetty `JettyLauncher` runs the identical servlets/filters with no Spring on the classpath.

**Migrating off Spring** is: delete `LwsServer` and `LwsServletConfig`, and ship `JettyLauncher`. The
bare launcher is also the deployment that can [terminate TLS itself](deployment.md).

The repository also carries the project's records: `COMPLIANCE.md` (the specification baseline, what
changed with each drafts update, and the deliberate divergences), `TODO.md` (open work by band), and
`SECURITY.md`.

## Test coverage

The suite mixes fast unit tests with end-to-end tests that boot the real stack over HTTP.

| Area | Tests |
|---|---|
| Core operations & processes | `OperationsConformanceTest`, `OperationsConformanceOwnerTest` — container representation + content negotiation, byte ranges (`206`/`416`), conditional replacement (`428`/`412`/`204`), `If-Modified-Since` (`304`), recursive `Depth: infinity` delete, metadata links, the linkset resource, problem+json, RFC 9530 digest fields, `Prefer: set-linkset` and link-relation filtering, JSON Patch. Also `ContainerSemanticsTest`, `ConditionalWriteTest`, `IfMatchTest`, `MandatoryPreconditionTest`, `ReservedNameTest`, `RdfFormatsTest`, `DigestFieldsTest`. |
| End-to-end | `EndToEndTest` — boots the bare-Jetty stack on a free port and drives CRUD, content negotiation, conditional requests, binary round-trip, delete guards, error codes, Merge Patch, subscriptions and the UI. |
| Authorization server & tokens | `LwsAuthorizationTest` — the embedded authorization server's metadata and token exchange, validation of the access tokens it (or a trusted external server) issues, the `as_uri`/`realm` challenge, and DPoP-bound tokens. |
| Authentication | `SsiCidValidatorTest`, `DidsAndMultikeyTest` (DID syntax, the `did:key` document, `did:web`, Multikey), `DidKeyValidatorTest`, `DidKeyToolTest`, `SamlValidatorTest`, `LwsCredentialValidatorTest`, `LwsOpenIdValidatorTest` (against an in-process `MockOidcProvider`), `OidcSsoRedirectTest`, `AuthenticationFilterTest`, `DpopValidatorTest`, `DpopNonceServiceTest`, `DpopHttpIntegrationTest`, `OutboundFetchPolicyTest`. |
| Authorization | `WacAclServiceTest` (owner control, public/authenticated, groups, `acl:origin`, inheritance, nearest-ACL override), `WacHttpIntegrationTest`, `ExistenceOracleTest`, `WriterLockAuthorizationTest`, `AccessGrantsTest`, `GrantIssuerAuthorityTest`, `AccessNotificationTest`. |
| Notifications | `WebhookDeliveryTest` — boots the server + a real inbox, subscribes, makes a change, and verifies the RFC 9421 signature and RFC 9530 digest against the storage description's verification method. Also `WebhookSigningAndKeysTest`, `NotificationAuthorizationTest`, `InboxSsrfTest`, `SubscriptionPurgeTest`. |
| Search | `SearchIndexTest`, `SearchIndexAuthzTest` (the authorization guarantees + pagination). |
| SPARQL endpoint | `FusekiSparqlEndpointTest`. |
| Storage / patch / config | `Tdb2RdfStoreTest`, `FileSystemBinaryStoreTest`, `DeleteAtomicityTest`, `QuotaTest`, `ContainerPaginationTest`, `ResourceServiceListingTest`, `JsonMergePatchTest`, `JsonPatchTest`, `SparqlUpdateGuardTest`, `StorageDescriptionServiceTest`, `LwsConfigurationTest`, `FailClosedConfigurationTest`. |
| Deployment | `ReverseProxyForwardingTest` (`lws.behind-proxy`), `CorsTest`, `AcmeSupportTest`. |
| Management UI | `LwsUiTest` (WicketTester): capability gating, resource creation, ACL editing; `LoginPageTest`. |

## Conventions

- **No Spring** outside the two bootstrap classes. New protocol logic is a plain Jakarta servlet/
  filter or a framework-free service object wired in `LwsComponents`.
- **Configuration** is added to `LwsConfiguration` via the typed, validating accessors so a bad value
  [fails fast](configuration.md#fail-fast-validation) with an actionable message — and documented in
  `lws.example.properties`, the README's configuration table and [Configuration](configuration.md).
- **Authorization** decisions go through the `Authorizer` so the HTTP API, UI and search services
  enforce the same rules.
- **Specification changes** are recorded in `COMPLIANCE.md` against the drafts baseline they follow.

## Documentation

This site is built from the Markdown in the `docs/` folder of the
[`lws-server`](https://github.com/ebremer/lws-server) repository — see `docs/README.md` for
how to preview locally and publish via GitHub Pages.
