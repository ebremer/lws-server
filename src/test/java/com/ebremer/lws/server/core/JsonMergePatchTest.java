package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.nio.charset.StandardCharsets;
import jakarta.json.JsonValue;
import org.junit.jupiter.api.Test;

/**
 * Tests {@link JsonMergePatch} against the examples in RFC 7386 Appendix A.
 *
 * @author Erich Bremer
 */
class JsonMergePatchTest {

    @Test
    void rfc7386Examples() {
        check("{\"a\":\"b\"}", "{\"a\":\"c\"}", "{\"a\":\"c\"}");
        check("{\"a\":\"b\"}", "{\"b\":\"c\"}", "{\"a\":\"b\",\"b\":\"c\"}");
        check("{\"a\":\"b\"}", "{\"a\":null}", "{}");
        check("{\"a\":\"b\",\"b\":\"c\"}", "{\"a\":null}", "{\"b\":\"c\"}");
        check("{\"a\":[\"b\"]}", "{\"a\":\"c\"}", "{\"a\":\"c\"}");
        check("{\"a\":\"c\"}", "{\"a\":[\"b\"]}", "{\"a\":[\"b\"]}");
        check("{\"a\":{\"b\":\"c\"}}", "{\"a\":{\"b\":\"d\",\"c\":null}}", "{\"a\":{\"b\":\"d\"}}");
        check("{\"a\":[{\"b\":\"c\"}]}", "{\"a\":[1]}", "{\"a\":[1]}");
        check("[\"a\",\"b\"]", "[\"c\",\"d\"]", "[\"c\",\"d\"]");
        check("{\"a\":\"b\"}", "[\"c\"]", "[\"c\"]");
        check("{\"a\":\"foo\"}", "null", "null");
        check("{\"a\":\"foo\"}", "\"bar\"", "\"bar\"");
        check("{\"e\":null}", "{\"a\":1}", "{\"e\":null,\"a\":1}");
        check("[1,2]", "{\"a\":\"b\",\"c\":null}", "{\"a\":\"b\"}");
        check("{}", "{\"a\":{\"bb\":{\"ccc\":null}}}", "{\"a\":{\"bb\":{}}}");
    }

    private static void check(String target, String patch, String expected) {
        JsonValue result = JsonMergePatch.apply(read(target), read(patch));
        assertEquals(read(expected), result, "merge(" + target + ", " + patch + ")");
    }

    private static JsonValue read(String json) {
        return JsonMergePatch.read(json.getBytes(StandardCharsets.UTF_8));
    }
}
