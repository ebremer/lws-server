package com.ebremer.lws.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot entry point for the LWS server. Spring Boot is used solely to bootstrap the
 * embedded Jetty servlet container; all protocol logic lives in framework-free classes wired by
 * {@link LwsComponents} and registered by {@link LwsServletConfig}.
 *
 * <p>To run on a bare Eclipse Jetty server instead (no Spring), use
 * {@link com.ebremer.lws.server.JettyLauncher}.
 *
 * @author Erich Bremer
 */
@SpringBootApplication
public class LwsServer {

    public static void main(String[] args) {
        SpringApplication.run(LwsServer.class, args);
    }
}
