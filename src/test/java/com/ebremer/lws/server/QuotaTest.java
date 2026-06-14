package com.ebremer.lws.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.util.Properties;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Tests the storage quota: with {@code lws.quota.max-bytes} set small, a binary write that would
 * push total stored content past the limit is refused with {@code 507 Insufficient Storage}, and
 * deleting content frees space for subsequent writes.
 *
 * @author Erich Bremer
 */
class QuotaTest {

    private static Server server;
    private static LwsComponents components;
    private static String baseUrl;
    private static HttpClient http;

    @BeforeAll
    static void start() throws Exception {
        int port = freePort();
        baseUrl = "http://localhost:" + port;
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUrl);
        p.setProperty("lws.data-dir", Files.createTempDirectory("lws-quota").toString());
        p.setProperty("lws.quota.max-bytes", "10");
        LwsConfiguration config = LwsConfiguration.of(p);
        components = LwsComponents.create(config);
        server = new Server(port);
        server.setHandler(JettyLauncher.buildHandler(components, config));
        server.start();
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void stop() throws Exception {
        if (server != null) {
            server.stop();
        }
        if (components != null) {
            components.close();
        }
    }

    @Test
    void writesBeyondQuotaAreRejectedAndDeletingFreesSpace() throws Exception {
        assertEquals(201, put("/a", "12345").statusCode()); // 5 bytes, total 5
        assertEquals(201, put("/b", "67890").statusCode()); // total 10 == limit

        // One more byte would exceed the 10-byte quota.
        assertEquals(507, put("/c", "x").statusCode());

        // Deleting /a frees 5 bytes, so the write now fits.
        assertEquals(204, delete("/a").statusCode());
        assertEquals(201, put("/c", "x").statusCode());
    }

    private static HttpResponse<String> put(String path, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "application/octet-stream")
                .PUT(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> delete(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(baseUrl + path)).DELETE().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
