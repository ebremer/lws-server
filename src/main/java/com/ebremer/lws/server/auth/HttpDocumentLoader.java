package com.ebremer.lws.server.auth;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default {@link DocumentLoader} that dereferences a document over HTTP(S), requesting JSON-LD /
 * DID / JSON representations. The target URL is validated against an {@link OutboundFetchPolicy}
 * (an SSRF guard) before any request, the connection and read are time-bounded, and the response
 * body is capped to {@link #MAX_BODY_BYTES} to bound memory from a hostile document.
 *
 * @author Erich Bremer
 */
public final class HttpDocumentLoader implements DocumentLoader {

    private static final Logger log = LoggerFactory.getLogger(HttpDocumentLoader.class);

    /** Maximum document size accepted (controlled-identifier / DID documents are small). */
    private static final long MAX_BODY_BYTES = 2L * 1024 * 1024;

    private final OutboundFetchPolicy fetchPolicy;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    public HttpDocumentLoader(OutboundFetchPolicy fetchPolicy) {
        this.fetchPolicy = fetchPolicy;
    }

    @Override
    public String load(String url) {
        if (!fetchPolicy.permits(url)) {
            log.debug("Refusing to load document {} (blocked by outbound-fetch policy)", url);
            return null;
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/ld+json, application/did+json, application/json")
                    .GET()
                    .build();
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() / 100 != 2) {
                log.debug("Document {} returned HTTP {}", url, response.statusCode());
                return null;
            }
            try (InputStream in = response.body()) {
                byte[] body = in.readNBytes((int) MAX_BODY_BYTES + 1);
                if (body.length > MAX_BODY_BYTES) {
                    log.debug("Document {} exceeds {} bytes; refusing", url, MAX_BODY_BYTES);
                    return null;
                }
                return new String(body, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            log.debug("Could not load document {}: {}", url, e.toString());
            return null;
        }
    }
}
