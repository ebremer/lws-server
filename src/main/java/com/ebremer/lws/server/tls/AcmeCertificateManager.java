package com.ebremer.lws.server.tls;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Supplier;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ebremer.lws.server.LwsConfiguration;

/**
 * Provisions and renews an X.509 certificate from an ACME CA (Let's Encrypt by default) using the
 * <a href="https://shredzone.org/maven/acme4j/">acme4j</a> client and the HTTP-01 challenge, and
 * assembles it into an in-memory PKCS12 {@link KeyStore} for Jetty's TLS connector.
 *
 * <p>State is persisted under {@link LwsConfiguration#tlsDir()}: the ACME <em>account</em> key, the
 * <em>domain</em> key, and the certificate chain (PEM). On startup an existing, not-yet-expiring
 * certificate is reused without contacting the CA; otherwise the HTTP-01 flow runs (the server must
 * be reachable over HTTP on {@link LwsConfiguration#tlsHttpPort()} for the {@link AcmeChallengeStore}
 * to be served by {@link AcmeChallengeServlet}).
 *
 * <p>The live ACME flow requires a publicly reachable domain and a real CA, so it cannot be
 * exercised by unit tests; only the key-store assembly and the surrounding wiring are tested.
 *
 * @author Erich Bremer
 */
public final class AcmeCertificateManager {

    private static final Logger log = LoggerFactory.getLogger(AcmeCertificateManager.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(120);
    private static final String ALIAS = "lws";

    private final LwsConfiguration config;
    private final AcmeChallengeStore challenges;
    private final Path accountKeyFile;
    private final Path domainKeyFile;
    private final Path chainFile;
    private final char[] keystorePassword; // guards an in-memory keystore only; never persisted

    public AcmeCertificateManager(LwsConfiguration config, AcmeChallengeStore challenges) {
        this.config = config;
        this.challenges = challenges;
        Path dir = config.tlsDir();
        this.accountKeyFile = dir.resolve("account.key");
        this.domainKeyFile = dir.resolve("domain.key");
        this.chainFile = dir.resolve("domain-chain.crt");
        this.keystorePassword = randomPassword();
    }

    /** The in-memory keystore password, for the connector's {@code SslContextFactory}. */
    public char[] keystorePassword() {
        return keystorePassword.clone();
    }

    /** Ensure a current certificate exists (acquiring one via ACME if needed) and return it as a keystore. */
    public KeyStore obtainKeyStore() throws Exception {
        if (!hasCurrentCertificate()) {
            acquire();
        }
        return buildKeyStore();
    }

    /** True when the stored certificate is missing or within the configured renewal window. */
    public boolean dueForRenewal() {
        try {
            if (!Files.exists(chainFile) || !Files.exists(domainKeyFile)) {
                return true;
            }
            Instant notAfter = leafCertificate().getNotAfter().toInstant();
            return Instant.now().plus(config.acmeRenewBeforeDays(), ChronoUnit.DAYS).isAfter(notAfter);
        } catch (Exception e) {
            log.warn("Could not read the stored certificate; treating it as due for renewal: {}", e.toString());
            return true;
        }
    }

    private boolean hasCurrentCertificate() {
        return Files.exists(chainFile) && Files.exists(domainKeyFile) && !dueForRenewal();
    }

    // ----- ACME flow -----

    private void acquire() throws AcmeException, IOException {
        Files.createDirectories(config.tlsDir());
        KeyPair accountKey = loadOrCreateKey(accountKeyFile, KeyPairUtils::createKeyPair);
        Session session = new Session(config.acmeDirectoryUrl());
        Account account = registerAccount(session, accountKey);
        KeyPair domainKey = loadOrCreateKey(domainKeyFile, () -> KeyPairUtils.createKeyPair(2048));

        log.info("Requesting an ACME certificate for {} from {}", config.acmeDomains(), config.acmeDirectoryUrl());
        Order order = account.newOrder().domains(config.acmeDomains()).create();
        try {
            for (Authorization auth : order.getAuthorizations()) {
                authorize(auth);
            }
            order.waitUntilReady(TIMEOUT);
            order.execute(domainKey);
            if (order.waitForCompletion(TIMEOUT) != Status.VALID) {
                throw new AcmeException("ACME order failed: "
                        + order.getError().map(Object::toString).orElse("unknown"));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AcmeException("Interrupted while completing the ACME order", e);
        }
        Certificate certificate = order.getCertificate();
        try (var writer = Files.newBufferedWriter(chainFile)) {
            certificate.writeCertificate(writer);
        }
        log.info("Obtained certificate for {} (expires {})", config.acmeDomains(),
                certificate.getCertificate().getNotAfter());
    }

    private Account registerAccount(Session session, KeyPair accountKey) throws AcmeException {
        AccountBuilder builder = new AccountBuilder().agreeToTermsOfService().useKeyPair(accountKey);
        if (!config.acmeEmail().isBlank()) {
            builder.addEmail(config.acmeEmail());
        }
        return builder.create(session);
    }

    private void authorize(Authorization auth) throws AcmeException, InterruptedException {
        if (auth.getStatus() == Status.VALID) {
            return;
        }
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.class)
                .orElseThrow(() -> new AcmeException("No HTTP-01 challenge offered for "
                        + auth.getIdentifier().getDomain()));
        challenges.put(challenge.getToken(), challenge.getAuthorization());
        try {
            challenge.trigger();
            if (challenge.waitForCompletion(TIMEOUT) != Status.VALID) {
                throw new AcmeException("HTTP-01 challenge failed for " + auth.getIdentifier().getDomain() + ": "
                        + challenge.getError().map(Object::toString).orElse("unknown"));
            }
        } finally {
            challenges.remove(challenge.getToken());
        }
    }

    // ----- key store assembly -----

    /** Build a PKCS12 keystore from the persisted domain key and certificate chain. */
    KeyStore buildKeyStore() throws Exception {
        KeyPair domainKey;
        try (var reader = Files.newBufferedReader(domainKeyFile)) {
            domainKey = KeyPairUtils.readKeyPair(reader);
        }
        List<X509Certificate> chain = new ArrayList<>();
        try (var in = Files.newInputStream(chainFile)) {
            for (var cert : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                chain.add((X509Certificate) cert);
            }
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(ALIAS, domainKey.getPrivate(), keystorePassword, chain.toArray(new X509Certificate[0]));
        return keyStore;
    }

    private X509Certificate leafCertificate() throws Exception {
        try (var in = Files.newInputStream(chainFile)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static KeyPair loadOrCreateKey(Path file, Supplier<KeyPair> factory) throws IOException {
        if (Files.exists(file)) {
            try (var reader = Files.newBufferedReader(file)) {
                return KeyPairUtils.readKeyPair(reader);
            }
        }
        KeyPair keyPair = factory.get();
        try (var writer = Files.newBufferedWriter(file)) {
            KeyPairUtils.writeKeyPair(keyPair, writer);
        }
        return keyPair;
    }

    private static char[] randomPassword() {
        byte[] bytes = new byte[24];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).toCharArray();
    }
}
