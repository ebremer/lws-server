package com.ebremer.lws.server;

/**
 * Thrown when {@link LwsConfiguration} encounters an invalid setting. Carries an actionable message —
 * the offending key, the value supplied, and what was expected — so a misconfiguration fails fast and
 * clearly instead of surfacing as a raw {@code NumberFormatException} or {@code IllegalArgumentException}
 * with no indication of which property is at fault.
 *
 * @author Erich Bremer
 */
public class LwsConfigurationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public LwsConfigurationException(String message) {
        super(message);
    }
}
