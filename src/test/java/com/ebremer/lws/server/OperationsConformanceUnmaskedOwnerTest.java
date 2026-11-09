package com.ebremer.lws.server;

import java.util.Properties;

/**
 * The lws10-core operations conformance suite for a configured owner, as in
 * {@link OperationsConformanceOwnerTest}, with {@code lws.mask-forbidden-as-not-found=false}: a
 * client without Read is told {@code 403}, not {@code 404}.
 *
 * <p><strong>What this pins.</strong> The owner may read everything, so masking should never be
 * what decides an answer to the owner, and every status the shared suite expects has to come out
 * the same with it off. It did not, once: a create in a container that does not exist was refused
 * by the servlet's pre-body check as forbidden (the owner authorizer allows nothing on an IRI with
 * no stored resource), and only the masking turned the owner's {@code 403} into the {@code 404}
 * lws10-core gives the <em>Target Not Found</em> outcome (w3c/lws-protocol #263). With masking off
 * the owner was told {@code 403} for a create the storage was permitted to make;
 * {@code createInAMissingContainerIsTargetNotFound} fails here without the fix.
 *
 * @author Erich Bremer
 */
class OperationsConformanceUnmaskedOwnerTest extends OperationsConformanceOwnerTest {

    @Override
    protected void configure(Properties p) {
        super.configure(p);
        p.setProperty("lws.mask-forbidden-as-not-found", "false");
    }
}
