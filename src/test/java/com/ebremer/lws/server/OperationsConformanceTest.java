package com.ebremer.lws.server;

import java.util.Properties;

/**
 * The lws10-core operations conformance suite run in the development posture: open mode, and no
 * {@code Authorization} header on any request.
 *
 * <p>Every assertion lives in {@link AbstractOperationsConformance}; this class contributes only the
 * posture. It is the historical shape of the suite, kept under its original name because
 * {@code COMPLIANCE.md} cites it by name as the evidence for the operations and processes it claims
 * conformance to.
 *
 * <p>Open mode is a real posture worth pinning — an operator who sets {@code lws.dev.open=true} on a
 * development box is entitled to a server that still speaks the protocol correctly — but it is only
 * half of the claim, because {@code DefaultAccessPolicy} short-circuits every read and write here.
 * {@link OperationsConformanceOwnerTest} runs the same assertions against a configured owner, which
 * is what makes the pair meaningful (finding M47).
 *
 * @author Erich Bremer
 */
class OperationsConformanceTest extends AbstractOperationsConformance {

    /**
     * Open mode: this posture asserts protocol behaviour, not authorization outcomes, so it opts in
     * to the development posture rather than configuring an owner. One property is the whole of it —
     * with {@code lws.owners} empty, {@code lws.dev.open} is what keeps
     * {@code validateAuthorizationPosture()} from refusing the configuration outright.
     */
    @Override
    protected void configure(Properties p) {
        p.setProperty("lws.dev.open", "true");
    }
}
