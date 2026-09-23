---
title: Deployment & TLS
nav_order: 12
---

# Deployment & TLS
{: .no_toc }

1. TOC
{:toc}

DPoP and WebID/OIDC assume the storage is reached over **TLS** in production. There are two ways to
get there — use one, not both.

## Option A — behind a reverse proxy (default model)

The server terminates **plain HTTP** and sits behind a reverse proxy (nginx, Caddy, Traefik, …) that
terminates HTTPS.

1. Set `lws.base-uri` to the **external** `https://` URL. DPoP `htu`, WebIDs, ACLs and every minted
   IRI come from this value (not the internal request scheme/host), so everything is correct even
   though the app speaks HTTP behind the proxy.
2. Set `lws.behind-proxy=true` so the server trusts `X-Forwarded-Proto` / `X-Forwarded-Host` /
   `Forwarded` (RFC 7239) from the proxy — making `request.isSecure()`, generated redirects and
   secure-cookie flags reflect the external HTTPS URL. Enable it **only** when a trusted proxy is in
   front and strips client-supplied forwarding headers (otherwise a client could spoof the scheme).
3. Set `lws.require-https=true` to fail fast if `base-uri` is not `https://` (loopback hosts stay
   exempt for local development).

Example nginx front end for a server on `127.0.0.1:8080`:

```nginx
server {
  listen 443 ssl;
  server_name storage.example;
  # ssl_certificate / ssl_certificate_key ...
  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto $scheme;   # https
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
  }
}
```

## Option B — terminate TLS in the server (ACME / Let's Encrypt)

The **bare-Jetty launcher** (`com.ebremer.lws.server.JettyLauncher`) can terminate TLS itself,
obtaining and renewing a certificate from an ACME CA (Let's Encrypt by default) via
[acme4j](https://acme4j.shredzone.org/) and the **HTTP-01** challenge. (The Spring Boot entry point is
intended for the reverse-proxy model above; TLS is wired into the bare launcher.)

**How it works.** The launcher starts the HTTP connector (`lws.tls.http-port`, default `80`),
provisions the certificate (serving the challenge at `/.well-known/acme-challenge/*`), then starts the
HTTPS connector (`lws.tls.port`, default `443`). Plain-HTTP requests other than the challenge are
redirected to HTTPS. The account key, domain key and certificate are cached under `lws.tls.dir`, so
restarts reuse a still-valid certificate; a daemon checks twice daily and renews within
`lws.tls.acme.renew-before-days` of expiry, hot-reloading the TLS context with no restart.

**Setup.**

1. Point DNS for your domain at the host, and make ports **80 and 443 publicly reachable** (the CA
   connects to port 80 to validate the HTTP-01 challenge). Run the launcher as a user permitted to
   bind those ports (e.g. `setcap` / `authbind`, a systemd socket, or root).
2. Configure (in `lws.properties` or via `-Dlws.*`):

   ```properties
   lws.base-uri=https://storage.example
   lws.tls.enabled=true
   lws.tls.acme.email=admin@storage.example
   lws.tls.acme.accept-terms-of-service=true     # required; agrees to the CA's Terms of Service
   # lws.tls.acme.domains=storage.example        # defaults to the lws.base-uri host
   # while testing, use the staging CA to avoid rate limits (its certs are NOT browser-trusted):
   # lws.tls.acme.directory-url=https://acme-staging-v02.api.letsencrypt.org/directory
   ```

3. Run the bare-Jetty launcher (it lives in the same jar):

   ```bash
   java -cp target/lws-server.jar -Dloader.main=com.ebremer.lws.server.JettyLauncher \
       org.springframework.boot.loader.launch.PropertiesLauncher
   # or, from a source checkout:
   mvn -q exec:java -Dexec.mainClass=com.ebremer.lws.server.JettyLauncher
   ```

**Notes.** Start with the **staging** directory URL to validate the setup (Let's Encrypt production
has strict rate limits); switch to production once it works, deleting `lws.tls.dir` so a fresh,
trusted certificate is ordered. Other challenge types (TLS-ALPN-01, DNS-01) and non-Let's-Encrypt CAs
are not wired up — but you can point `lws.tls.acme.directory-url` at any ACME CA that supports
HTTP-01.
