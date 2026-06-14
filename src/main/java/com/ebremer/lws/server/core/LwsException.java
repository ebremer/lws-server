package com.ebremer.lws.server.core;

/**
 * A protocol-level error that maps directly onto an HTTP status code.
 * Thrown by the service layer and translated to a response by the HTTP layer.
 *
 * @author Erich Bremer
 */
public class LwsException extends RuntimeException {

    private final int status;

    public LwsException(int status, String message) {
        super(message);
        this.status = status;
    }

    public LwsException(int status, String message, Throwable cause) {
        super(message, cause);
        this.status = status;
    }

    public int status() {
        return status;
    }

    // ----- Convenience factories for the common cases -----

    public static LwsException notFound(String iri) {
        return new LwsException(404, "Resource not found: " + iri);
    }

    public static LwsException badRequest(String message) {
        return new LwsException(400, message);
    }

    public static LwsException conflict(String message) {
        return new LwsException(409, message);
    }

    public static LwsException unsupportedMediaType(String message) {
        return new LwsException(415, message);
    }

    public static LwsException methodNotAllowed(String method) {
        return new LwsException(405, "Method not allowed: " + method);
    }

    public static LwsException forbidden(String message) {
        return new LwsException(403, message);
    }

    public static LwsException unauthorized(String message) {
        return new LwsException(401, message);
    }

    public static LwsException unavailableForLegalReasons(String message) {
        return new LwsException(451, message);
    }

    public static LwsException insufficientStorage(String message) {
        return new LwsException(507, message);
    }
}
