package com.ebremer.lws.server.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.util.Properties;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Which redirects {@link BasePathRedirectFilter} moves under the base URI's path, and which it
 * leaves alone.
 *
 * @author Erich Bremer
 */
class BasePathRedirectFilterTest {

    private static LwsConfiguration config(String baseUri) {
        Properties p = new Properties();
        p.setProperty("lws.base-uri", baseUri);
        p.setProperty("lws.owners", "https://owner.example/profile#me");
        p.setProperty("lws.behind-proxy", "true");
        return LwsConfiguration.of(p);
    }

    private static HttpServletRequest request(String url) {
        HttpServletRequest r = mock(HttpServletRequest.class);
        when(r.getRequestURL()).thenReturn(new StringBuffer(url));
        return r;
    }

    private final BasePathRedirectFilter filter =
            BasePathRedirectFilter.forConfig(config("https://example.org/lws"));
    private final HttpServletRequest atApp = request("https://example.org/app/");

    @Test
    void notInstalledAtTheRootOfAHost() {
        assertNull(BasePathRedirectFilter.forConfig(config("https://example.org")));
        assertNull(BasePathRedirectFilter.forConfig(config("https://example.org/")));
    }

    @Test
    void consoleRedirectsGainThePrefix() {
        assertEquals("https://example.org/lws/app/browse?p=%2Fa",
                filter.rewrite(atApp, "https://example.org/app/browse?p=%2Fa"));
        assertEquals("https://example.org/lws/app/browse", filter.rewrite(atApp, "./browse"));
        assertEquals("https://example.org/lws/app/login", filter.rewrite(atApp, "/app/login"));
        assertEquals("https://example.org/lws/callback?code=x", filter.rewrite(atApp, "/callback?code=x"));
    }

    @Test
    void otherRedirectsAreLeftAlone() {
        // the identity provider
        assertEquals("https://idp.example/auth?x=1", filter.rewrite(atApp, "https://idp.example/auth?x=1"));
        // already prefixed, or outside the console's trees
        assertEquals("https://example.org/lws/app/browse",
                filter.rewrite(atApp, "https://example.org/lws/app/browse"));
        assertEquals("https://example.org/node/1", filter.rewrite(atApp, "https://example.org/node/1"));
        // the same path on another origin
        assertEquals("https://other.example/app/browse",
                filter.rewrite(atApp, "https://other.example/app/browse"));
    }
}
