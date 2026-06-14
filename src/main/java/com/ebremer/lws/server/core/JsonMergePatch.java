package com.ebremer.lws.server.core;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;

/**
 * JSON Merge Patch as defined by <a href="https://www.rfc-editor.org/rfc/rfc7386">RFC 7386</a>.
 *
 * <p>The algorithm: if the patch is a JSON object, recursively merge it into the target (a member
 * whose value is {@code null} is removed; an object value is merged; any other value replaces);
 * if the patch is not an object, it replaces the target entirely.
 *
 * @author Erich Bremer
 */
public final class JsonMergePatch {

    private JsonMergePatch() {
    }

    /** Apply a JSON Merge Patch to a target value (RFC 7386 §2). */
    public static JsonValue apply(JsonValue target, JsonValue patch) {
        if (patch == null || patch.getValueType() != JsonValue.ValueType.OBJECT) {
            return patch; // non-object patch replaces the target wholesale
        }
        JsonObject patchObject = patch.asJsonObject();
        JsonObject targetObject = (target != null && target.getValueType() == JsonValue.ValueType.OBJECT)
                ? target.asJsonObject() : JsonValue.EMPTY_JSON_OBJECT;

        JsonObjectBuilder result = Json.createObjectBuilder();
        // carry over target members the patch does not mention
        for (Map.Entry<String, JsonValue> entry : targetObject.entrySet()) {
            if (!patchObject.containsKey(entry.getKey())) {
                result.add(entry.getKey(), entry.getValue());
            }
        }
        // apply the patch members (null => remove, otherwise merge/replace)
        for (Map.Entry<String, JsonValue> entry : patchObject.entrySet()) {
            JsonValue patchValue = entry.getValue();
            if (patchValue.getValueType() == JsonValue.ValueType.NULL) {
                continue; // remove member
            }
            result.add(entry.getKey(), apply(targetObject.get(entry.getKey()), patchValue));
        }
        return result.build();
    }

    /** Apply a JSON Merge Patch to a JSON document, both given as UTF-8 bytes. */
    public static byte[] apply(byte[] targetJson, byte[] patchJson) {
        return apply(read(targetJson), read(patchJson)).toString().getBytes(StandardCharsets.UTF_8);
    }

    public static JsonValue read(byte[] json) {
        try (JsonReader reader = Json.createReader(new ByteArrayInputStream(json))) {
            return reader.readValue();
        }
    }
}
