package com.ebremer.lws.server.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Set;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.core.LwsException;

/**
 * Unit tests for RFC 9530 digest-field formatting, {@code Want-*} algorithm selection, and inbound
 * {@code Content-Digest} verification.
 *
 * @author Erich Bremer
 */
class DigestFieldsTest {

    @Test
    void formatsAndVerifies() {
        byte[] content = "hello".getBytes(StandardCharsets.UTF_8);
        String header = DigestFields.format("sha-256", content);
        assertTrue(header.startsWith("sha-256=:") && header.endsWith(":"), header);
        DigestFields.verify(header, content); // matches -> no throw
        assertThrows(LwsException.class, () -> DigestFields.verify(header, "world".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void sha256FromHexEqualsFormat() throws Exception {
        byte[] content = "abc".getBytes(StandardCharsets.UTF_8);
        String hex = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        assertEquals(DigestFields.format("sha-256", content), DigestFields.sha256FromHex(hex));
    }

    @Test
    void choosesPreferredAvailableAlgorithm() {
        assertEquals("sha-512",
                DigestFields.chooseAlgorithm("sha-256=3, sha-512=10", DigestFields.SUPPORTED_SET).orElseThrow());
        assertEquals("sha-256",
                DigestFields.chooseAlgorithm("sha-256=3, sha-512=10", Set.of("sha-256")).orElseThrow());
        assertTrue(DigestFields.chooseAlgorithm("md5=10", DigestFields.SUPPORTED_SET).isEmpty()); // unsupported
        assertTrue(DigestFields.chooseAlgorithm("sha-256=0", DigestFields.SUPPORTED_SET).isEmpty()); // weight 0
        assertTrue(DigestFields.chooseAlgorithm(null, DigestFields.SUPPORTED_SET).isEmpty());
    }

    @Test
    void ignoresUnsupportedAndRejectsMalformed() {
        DigestFields.verify(null, "x".getBytes(StandardCharsets.UTF_8));           // absent -> ok
        DigestFields.verify("md5=:abcd:", "x".getBytes(StandardCharsets.UTF_8));   // unsupported alg -> ignored
        assertThrows(LwsException.class,
                () -> DigestFields.verify("sha-256=:not valid base64!:", "x".getBytes(StandardCharsets.UTF_8)));
    }
}
