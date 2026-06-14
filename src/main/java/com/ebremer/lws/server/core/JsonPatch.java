package com.ebremer.lws.server.core;

import java.io.ByteArrayInputStream;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonReader;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;

/**
 * JSON Patch as defined by <a href="https://www.rfc-editor.org/rfc/rfc6902">RFC 6902</a>: a sequence
 * of operations ({@code add}/{@code remove}/{@code replace}/{@code move}/{@code copy}/{@code test})
 * applied to a JSON document and addressed by <a href="https://www.rfc-editor.org/rfc/rfc6901">RFC
 * 6901</a> JSON Pointers.
 *
 * <p>This is a thin wrapper over the {@code jakarta.json} implementation that maps its failures to
 * LWS HTTP errors: a malformed patch body is a {@code 400}; a patch that cannot be applied to the
 * target (an unresolvable pointer, or a failed {@code test}) is a {@code 409}.
 *
 * @author Erich Bremer
 */
public final class JsonPatch {

    private JsonPatch() {
    }

    /** Parse a JSON Patch request body, which MUST be a JSON array of operation objects (RFC 6902 §3). */
    public static JsonArray read(byte[] body) {
        try (JsonReader reader = Json.createReader(new ByteArrayInputStream(body))) {
            JsonValue value = reader.readValue();
            if (value.getValueType() != JsonValue.ValueType.ARRAY) {
                throw LwsException.badRequest("JSON Patch body must be a JSON array (RFC 6902)");
            }
            return value.asJsonArray();
        } catch (JsonException | IllegalStateException e) {
            throw LwsException.badRequest("Invalid JSON Patch: " + e.getMessage());
        }
    }

    /** Parse the JSON document (object or array) that a patch is applied to. */
    public static JsonStructure readStructure(byte[] json) {
        try (JsonReader reader = Json.createReader(new ByteArrayInputStream(json))) {
            return reader.read();
        } catch (JsonException | IllegalStateException e) {
            throw LwsException.badRequest("Target is not a JSON document: " + e.getMessage());
        }
    }

    /** Apply a JSON Patch to a target document (RFC 6902 §4). */
    public static JsonStructure apply(JsonStructure target, JsonArray patch) {
        try {
            return Json.createPatch(patch).apply(target);
        } catch (JsonException e) {
            // A failed `test`, an unresolvable pointer, or an op against a missing member: the patch
            // is well-formed JSON but cannot be applied to this document.
            throw LwsException.conflict("JSON Patch could not be applied: " + e.getMessage());
        }
    }
}
