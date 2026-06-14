package com.ebremer.lws.server.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.nio.charset.StandardCharsets;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the RFC 6902 JSON Patch wrapper: operation application and the mapping of
 * malformed-patch (400) and unapplicable-patch (409) failures to LWS errors.
 *
 * @author Erich Bremer
 */
class JsonPatchTest {

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void appliesAddRemoveReplace() {
        JsonStructure target = JsonPatch.readStructure(bytes("{\"a\":1,\"b\":2}"));
        JsonStructure result = JsonPatch.apply(target, JsonPatch.read(bytes(
                "[{\"op\":\"add\",\"path\":\"/c\",\"value\":3},"
                        + "{\"op\":\"remove\",\"path\":\"/b\"},"
                        + "{\"op\":\"replace\",\"path\":\"/a\",\"value\":9}]")));
        JsonObject obj = result.asJsonObject();
        assertEquals(9, obj.getInt("a"));
        assertEquals(3, obj.getInt("c"));
        assertFalse(obj.containsKey("b"));
    }

    @Test
    void rejectsNonArrayPatchAs400() {
        LwsException ex = assertThrows(LwsException.class, () -> JsonPatch.read(bytes("{\"op\":\"add\"}")));
        assertEquals(400, ex.status());
    }

    @Test
    void failedTestIsConflict() {
        JsonStructure target = JsonPatch.readStructure(bytes("{\"a\":1}"));
        LwsException ex = assertThrows(LwsException.class, () -> JsonPatch.apply(target,
                JsonPatch.read(bytes("[{\"op\":\"test\",\"path\":\"/a\",\"value\":2}]"))));
        assertEquals(409, ex.status());
    }

    @Test
    void unresolvablePathIsConflict() {
        JsonStructure target = JsonPatch.readStructure(bytes("{\"a\":1}"));
        LwsException ex = assertThrows(LwsException.class, () -> JsonPatch.apply(target,
                JsonPatch.read(bytes("[{\"op\":\"remove\",\"path\":\"/nope\"}]"))));
        assertEquals(409, ex.status());
    }
}
