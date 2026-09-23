---
title: Deployment & TLS
nav_order: 12
---

# Deployment & TLS
{: .no_toc }

1. TOC
{:toc}

DPoP, WebID/OIDC and the LWS authorization flow assume the storage is reached over **TLS** in
production. There are two ways to get there — use one, not both.

## Option A — behind a reverse proxy (default model)

The server terminates **plain HTTP** and sits behind a reverse proxy (nginx, Apache, Caddy, Traefik,
…) that terminates HTTPS.

1. Set `lws.base-uri` to the **external** `https://` URL. DPoP `htu`, WebIDs, ACLs, the authorization
   server's issuer and every minted IRI come from this value (not the internal request scheme/host),
   so everything is correct even though the app speaks HTTP behind the proxy.
2. Set `lws.listen-port` to the port the proxy forwards to, if it is not the base URI's port (an
   `https://` base URI with no port would otherwise mean `8080`). With the Spring Boot entry point,
   add `-Dserver.address=127.0.0.1` to keep that plain-HTTP port on loopback.
3. Set `lws.behind-proxy=true` so the server trusts `X-Forwarded-Proto` / `X-Forwarded-Host` /
   `Forwarded` (RFC 7239) from the proxy — making `request.isSecure()`, generated redirects,
   secure-cookie flags and HSTS reflect the external HTTPS URL. Enable it **only** when a trusted
   proxy is in front and strips client-supplied forwarding headers (otherwise a client could spoof the
   scheme).
4. Set `lws.require-https=true` to fail fast if `base-uri` is not `https://` (loopback hosts stay
   exempt for local development).

The proxy must pass every method through, including the HTTP **`QUERY`** method that
[Type Search](search-type-index.md) uses, and must not rewrite the `Authorization` and `DPoP` headers.

### At the root of a host

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

### Under a path prefix

The storage can share a host with another site — for example `https://example.org/lws/` beside a
CMS at `/`. The server itself always serves from `/`; the proxy strips the prefix, and
`lws.base-uri` carries it, so every IRI the server mints (resources, `Location`, `Link`, the
storage description, the issuer) includes it:

```properties
lws.base-uri=https://example.org/lws
lws.listen-port=8090
lws.behind-proxy=true
lws.require-https=true
```

Three paths go to the server, and nothing else:

| External | Internal | Why |
|---|---|---|
| `/lws/…` | `/…` | the storage (the proxy strips `/lws`) |
| `/lws` | — | redirect to `/lws/`, the storage URI |
| `/.well-known/lws-configuration/lws` | `/.well-known/lws-configuration` | the authorization server's metadata. Its issuer is `https://example.org/lws`, and [RFC 8414 §3.1](https://www.rfc-editor.org/rfc/rfc8414#section-3.1) puts the metadata of an issuer with a path *between the host and the path*, so that is where clients look |

Apache (`mod_proxy`, `mod_proxy_http`, `mod_headers`), inside the `:443` virtual host:

```apache
RequestHeader set X-Forwarded-Proto "https"
ProxyPreserveHost On

RedirectMatch 301 ^/lws$ /lws/
ProxyPass        /lws/ http://127.0.0.1:8090/ nocanon
ProxyPassReverse /lws/ http://127.0.0.1:8090/
ProxyPass /.well-known/lws-configuration/lws http://127.0.0.1:8090/.well-known/lws-configuration
```

nginx, inside the `server` block:

```nginx
location = /lws { return 301 /lws/; }
location /lws/ {
  proxy_pass http://127.0.0.1:8090/;              # trailing slash: strips /lws
  proxy_set_header Host              $host;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Host  $host;
  proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
}
location = /.well-known/lws-configuration/lws {
  proxy_pass http://127.0.0.1:8090/.well-known/lws-configuration;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Host  $host;
}
```

Check it from outside: `curl https://example.org/lws/` returns the storage description with
`"id": "https://example.org/lws/"`, `curl https://example.org/.well-known/lws-configuration/lws`
returns metadata whose `issuer` is `https://example.org/lws`, and an anonymous request to a private
resource gets `WWW-Authenticate: Bearer as_uri="https://example.org/lws", realm="https://example.org/lws/"`.

The [management UI](management-ui.md) works under the prefix too (`https://example.org/lws/app/`):
its redirects are moved back under `lws.base-uri`, and its session cookie is scoped to `/lws`, so
the other site on the host never receives it.

If the host already sets CORS headers for the whole site (for example `Header always set
Access-Control-Allow-Origin *` on `<Location />`), those apply to `/lws/` too and replace the
server's own [CORS policy](configuration.md#browser-access-cors); exclude the prefix from them.

### Running as a service

A systemd unit for the jar, run as an unprivileged `lws` user with `lws.properties` in the working
directory:

```ini
[Unit]
Description=lws-server
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=lws
Group=lws
WorkingDirectory=/srv/lws-server
ExecStart=/usr/bin/java -Xmx512m -Dserver.address=127.0.0.1 -jar /srv/lws-server/lws-server.jar
SuccessExitStatus=143
Restart=on-failure
RestartSec=10
UMask=0077

[Install]
WantedBy=multi-user.target
```

`SuccessExitStatus=143` treats the JVM's exit on `SIGTERM` as a clean stop.

## Option B — terminate TLS in the server (ACME / Let's Encrypt)

The **bare-Jetty launcher** (`com.ebremer.lws.server.JettyLauncher`) can terminate TLS itself,
obtaining and renewing a certificate from an ACME CA (Let's Encrypt by default) via
[acme4j](https://acme4j.shredzone.org/) and the **HTTP-01** challenge. The Spring Boot entry point is
intended for the reverse-proxy model above: it ignores `lws.tls.enabled` (and logs a warning saying
so) and serves plain HTTP.

**How it works.** The launcher starts the HTTP connector (`lws.tls.http-port`, default `80`),
provisions the certificate (serving the challenge at `/.well-known/acme-challenge/*`), then starts the
HTTPS connector (`lws.tls.port`, default `443`). Plain-HTTP requests other than the challenge are
redirected to HTTPS. The account key, domain key and certificate are cached under `lws.tls.dir`
(created owner-only), so restarts reuse a still-valid certificate; a daemon checks twice daily and
renews within `lws.tls.acme.renew-before-days` of expiry, hot-reloading the TLS context with no
restart.

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
HTTP-01. `Strict-Transport-Security` (`lws.hsts.max-age-seconds`) is sent on responses served over
TLS.
