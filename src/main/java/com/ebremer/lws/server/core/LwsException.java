package com.ebremer.lws.server.core;

/**
 * A protocol-level error that maps directly onto an HTTP status code.
 * Thrown by the service layer and translated to a response by the HTTP layer.
 *
 * @author Erich Bremer
 */
public class LwsException extends RuntimeException {

    private final int status;
    private final String title;

    public LwsException(int status, String message) {
        super(message);
        this.status = status;
        this.title = null;
    }

    public LwsException(int status, String message, Throwable cause) {
        super(message, cause);
        this.status = status;
        this.title = null;
    }

    private LwsException(int status, String title, String detail) {
        super(detail);
        this.status = status;
        this.title = title;
    }

    public int status() {
        return status;
    }

    /**
     * A short summary of the problem for an RFC 9457 {@code title}, or {@code null} to use the
     * status code's reason phrase, which is what almost every refusal here does.
     */
    public String title() {
        return title;
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

    /**
     * A {@code 409} whose problem detail carries a title of its own, for a refusal the
     * specification describes with one (lws10-core's example of moving a container into one of its
     * own descendants).
     */
    public static LwsException conflict(String title, String detail) {
        return new LwsException(409, title, detail);
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

    /** A conditional write whose {@code If-Match} did not match the stored entity-tag. */
    public static LwsException preconditionFailed(String message) {
        return new LwsException(412, message);
    }

    /** A write that must have been conditional and was not (lws10-core update-resource). */
    public static LwsException preconditionRequired(String message) {
        return new LwsException(428, message);
    }

    public static LwsException unavailableForLegalReasons(String message) {
        return new LwsException(451, message);
    }

    public static LwsException insufficientStorage(String message) {
        return new LwsException(507, message);
    }
}
