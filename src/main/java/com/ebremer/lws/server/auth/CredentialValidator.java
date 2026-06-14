package com.ebremer.lws.server.auth;

import java.util.Optional;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Validates one kind of LWS authentication credential (an authentication suite) and, if valid,
 * returns the authenticated {@link LwsPrincipal}. Implementations return {@link Optional#empty()}
 * for credentials they do not recognize or cannot verify.
 *
 * @author Erich Bremer
 */
public interface CredentialValidator {

    Optional<LwsPrincipal> validate(String credential);
}
