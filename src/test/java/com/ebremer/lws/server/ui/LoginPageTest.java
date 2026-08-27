package com.ebremer.lws.server.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Properties;
import java.util.function.Consumer;
import org.apache.jena.query.DatasetFactory;
import org.apache.wicket.util.tester.FormTester;
import org.apache.wicket.util.tester.WicketTester;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.TestDirs;
import com.ebremer.lws.server.auth.AudiencePolicy;
import com.ebremer.lws.server.auth.DidKeyValidator;
import com.ebremer.lws.server.auth.HttpDocumentLoader;
import com.ebremer.lws.server.auth.LwsCredentialValidator;
import com.ebremer.lws.server.auth.LwsOpenIdValidator;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;
import com.ebremer.lws.server.auth.SsiCidValidator;
import com.ebremer.lws.server.auth.WacAclService;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;
import com.ebremer.lws.server.tools.DidKeyTool;

/**
 * {@link LoginPage} is the console's front door — it hands out identities — and it had no test of
 * its own. {@link LwsUiTest} attaches a principal by calling {@code LwsSession.signIn} directly, so
 * every gate on the page itself was unexecuted: the {@code lws.ui.dev-login} switch, the loopback
 * and behind-a-proxy conditions on developer sign-in, the token form's three outcomes, and the
 * single-sign-on box.
 *
 * <p>The one that matters most is {@link
 * #theDevSignInHandlerRechecksTheAddressRatherThanTrustingTheRenderedForm()}. Developer sign-in
 * signs the caller in as <em>any WebID they name</em>, and Wicket restores the page instance from
 * its store on submit — so the form stays visible and submittable for whoever holds its (short,
 * per-session) callback URL, whatever address the submit arrives from. The production code says so
 * in a comment: <q>Whether a control is shown and whether it may run are different questions.</q>
 * Nothing tested the second half.
 *
 * <p>Deliberately not folded into {@code LwsUiTest}: that class builds one fixed
 * {@link LwsWebApplication} in {@code @BeforeEach}, and these tests need {@code lws.ui.dev-login},
 * {@code lws.behind-proxy} and the OIDC keys to vary. {@link LwsConfiguration} is immutable and the
 * application holds one instance, which is also why the recheck test moves the client address rather
 * than the configuration.
 *
 * @author Erich Bremer
 */
class LoginPageTest {

    /**
     * A fresh data directory per test; swept by the next run where the platform will not let this
     * one delete it — see {@link TestDirs}. {@code @TempDir} must not be used in this suite.
     */
    private final Path tempDir = TestDirs.create();

    /** Loopback, so {@code validateAuthorizationPosture} permits {@code lws.ui.dev-login}. */
    private static final String BASE = "http://localhost:8080";
    private static final String ALICE = "https://alice.example/profile#me";

    /** RFC 5737 TEST-NET-3: a documentation address, and definitively not a loopback one. */
    private static final String ELSEWHERE = "203.0.113.9";

    // The operator-facing strings the page promises. Asserting them, rather than merely that "some
    // message appeared", is what makes them a contract: each one names the setting to change.
    private static final String DEV_LOGIN_DISABLED =
            "Developer sign-in is disabled. Set lws.ui.dev-login=true to enable it (development only).";
    private static final String DEV_LOGIN_NOT_FROM_HERE =
            "Developer sign-in is enabled but not available from this address: it is offered "
                    + "only to loopback clients, and never when lws.behind-proxy=true.";
    private static final String DEV_LOGIN_REFUSED = "Developer sign-in is not available for this request.";
    private static final String NO_TOKEN = "Paste an ID token.";
    private static final String TOKEN_REJECTED =
            "Token rejected (invalid/expired, or issuer not trusted by the subject).";

    /** Distinguishes the blob directories when one test builds more than one application. */
    private int applications;

    private WicketTester tester(boolean devLogin, boolean behindProxy) {
        return tester(p -> {
            if (devLogin) {
                p.setProperty("lws.ui.dev-login", "true");
            }
            if (behindProxy) {
                p.setProperty("lws.behind-proxy", "true");
            }
        });
    }

    /**
     * The whole console stack over an in-memory dataset — no Jetty, no sockets, and no outbound
     * fetch: {@code AudiencePolicy.permitAll()} and a null-returning document loader keep the
     * credential validators offline, and a {@code did:key} token needs neither.
     */
    private WicketTester tester(Consumer<Properties> extraConfiguration) {
        Tdb2RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        FileSystemBinaryStore blobs = new FileSystemBinaryStore(tempDir.resolve("blobs" + applications++));
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.access-control", "wac");
        p.setProperty("lws.owners", ALICE);
        p.setProperty("lws.public-read", "true");
        extraConfiguration.accept(p);
        LwsConfiguration config = LwsConfiguration.of(p);
        WacAclService wac = new WacAclService(store, config);
        ResourceService rs = new ResourceService(store, blobs, new ResourceRegistry(), wac, config,
                Clock.systemUTC());
        rs.ensureStorageRoot();
        wac.bootstrapRootAcl();
        OutboundFetchPolicy permitAll = OutboundFetchPolicy.permitAll();
        AudiencePolicy anyAudience = AudiencePolicy.permitAll();
        LwsCredentialValidator credentials = new LwsCredentialValidator(
                new LwsOpenIdValidator(permitAll, new HttpDocumentLoader(permitAll), anyAudience),
                new SsiCidValidator(url -> null, anyAudience, 0),
                new DidKeyValidator(anyAudience, 0), null);
        return new WicketTester(new LwsWebApplication(rs, config, wac, credentials));
    }

    /**
     * Mark the next request as a same-origin navigation, which is what a browser sends for a form
     * the console itself rendered. Wicket's resource-isolation (CSRF) listener refuses component
     * callbacks that cannot be shown to be same-origin, so a submit without this never reaches
     * {@code onSubmit}. Lower-case: the mock request's header map is case-sensitive, unlike a real
     * container's. {@code LwsUiTest.sameOrigin} documents the same trap.
     */
    private static void sameOrigin(WicketTester tester) {
        tester.getRequest().addHeader("sec-fetch-site", "same-origin");
    }

    private static LwsSession sessionOf(WicketTester tester) {
        return (LwsSession) tester.getSession();
    }

    @Test
    void devSignInIsHiddenAndExplainedWhenItIsNotConfigured() {
        WicketTester tester = tester(false, false);
        tester.startPage(LoginPage.class);

        tester.assertRenderedPage(LoginPage.class);
        tester.assertInvisible("devForm");
        tester.assertVisible("devDisabled");
        tester.assertLabel("devDisabled", DEV_LOGIN_DISABLED);
    }

    /** The mock request's remote address defaults to {@code 127.0.0.1}, i.e. a direct local client. */
    @Test
    void devSignInIsOfferedToALoopbackClientWhenConfigured() {
        WicketTester tester = tester(true, false);
        tester.startPage(LoginPage.class);

        tester.assertVisible("devForm");
        tester.assertVisible("devForm:webId");
        tester.assertInvisible("devDisabled");
    }

    @Test
    void devSignInIsWithheldFromANonLoopbackClient() {
        WicketTester tester = tester(true, false);
        tester.getRequest().setRemoteAddr(ELSEWHERE);
        tester.startPage(LoginPage.class);

        tester.assertInvisible("devForm");
        tester.assertVisible("devDisabled");
        // The configured-but-unavailable wording, not the "it is switched off" one: the two differ,
        // and telling an operator to set a flag that is already set sends them the wrong way.
        tester.assertLabel("devDisabled", DEV_LOGIN_NOT_FROM_HERE);
    }

    /**
     * Behind a reverse proxy the client address is whatever {@code ForwardedRequestCustomizer} took
     * from a header, so it is supplied by the caller and the loopback test means nothing. The
     * request here <em>is</em> from {@code 127.0.0.1} and is still refused: that is the point.
     */
    @Test
    void devSignInIsWithheldBehindAProxyEvenFromALoopbackAddress() {
        WicketTester tester = tester(true, true);
        assertEquals("127.0.0.1", tester.getRequest().getRemoteAddr(),
                "the client really is loopback, so only lws.behind-proxy can be what withholds the form");
        tester.startPage(LoginPage.class);

        tester.assertInvisible("devForm");
        tester.assertLabel("devDisabled", DEV_LOGIN_NOT_FROM_HERE);
    }

    /**
     * Rendered from loopback, submitted from elsewhere. Wicket restores the page instance from its
     * store, so {@code devForm} is still visible and its callback still invokable — the address in
     * the request is the only thing that changed, and it is the only thing that may refuse the
     * sign-in. If {@code onSubmit} trusted the rendered form, this would sign the caller in as Alice.
     */
    @Test
    void theDevSignInHandlerRechecksTheAddressRatherThanTrustingTheRenderedForm() {
        WicketTester tester = tester(true, false);
        tester.startPage(LoginPage.class);
        tester.assertVisible("devForm");

        FormTester form = tester.newFormTester("devForm");
        form.setValue("webId", ALICE);
        tester.getRequest().setRemoteAddr(ELSEWHERE);
        sameOrigin(tester);
        form.submit();

        assertFalse(sessionOf(tester).isSignedIn(),
                "a submit from a non-loopback address must not attach an identity");
        tester.assertRenderedPage(LoginPage.class);
        tester.assertErrorMessages(DEV_LOGIN_REFUSED);
    }

    @Test
    void signingInWithAWebIdAttachesThatIdentityToTheSession() {
        WicketTester tester = tester(true, false);
        tester.startPage(LoginPage.class);

        FormTester form = tester.newFormTester("devForm");
        form.setValue("webId", ALICE);
        sameOrigin(tester);
        form.submit();

        LwsSession session = sessionOf(tester);
        assertTrue(session.isSignedIn(), "the developer form must sign the caller in");
        assertEquals(ALICE, session.getPrincipal().webId());
        assertEquals("urn:lws:dev-login", session.getPrincipal().issuer(),
                "a developer sign-in is asserted by this server, not vouched for by any issuer, and "
                        + "the principal must say so");
        tester.assertRenderedPage(BrowsePage.class);
    }

    /**
     * A blank WebID is the documented way to drop back to anonymous browsing. What it must not do is
     * mint a principal whose WebID is the empty string, which would be an authenticated agent that
     * no ACL names and no owner list contains.
     */
    @Test
    void submittingABlankWebIdBrowsesAnonymouslyInsteadOfSigningIn() {
        WicketTester tester = tester(true, false);
        tester.startPage(LoginPage.class);

        FormTester form = tester.newFormTester("devForm");
        form.setValue("webId", "   ");
        sameOrigin(tester);
        form.submit();

        assertFalse(sessionOf(tester).isSignedIn(), "a blank WebID must not become an identity");
        tester.assertRenderedPage(BrowsePage.class);
        tester.assertNoErrorMessage();
    }

    /** Whitespace only — what a botched paste produces — must be treated as no token at all. */
    @Test
    void anEmptyTokenIsRefused() {
        WicketTester tester = tester(false, false);
        tester.startPage(LoginPage.class);

        FormTester form = tester.newFormTester("tokenForm");
        form.setValue("token", "   ");
        sameOrigin(tester);
        form.submit();

        assertFalse(sessionOf(tester).isSignedIn());
        tester.assertRenderedPage(LoginPage.class);
        tester.assertErrorMessages(NO_TOKEN);
    }

    @Test
    void aTokenThatDoesNotValidateIsRefusedWithoutSigningIn() {
        WicketTester tester = tester(false, false);
        tester.startPage(LoginPage.class);

        FormTester form = tester.newFormTester("tokenForm");
        form.setValue("token", "not-a-token");
        sameOrigin(tester);
        form.submit();

        assertFalse(sessionOf(tester).isSignedIn(),
                "a credential the validator rejects must not attach an identity");
        tester.assertRenderedPage(LoginPage.class);
        tester.assertErrorMessages(TOKEN_REJECTED);
    }

    /**
     * The token form's success path, which is what makes it genuinely covered rather than merely
     * exercised through its two refusals. A {@code did:key} credential is self-signed and its
     * verification key comes out of the identifier, so this runs {@code LwsCredentialValidator} into
     * {@code DidKeyValidator} with no network at all. A null audience is fine here because the
     * factory wires {@code AudiencePolicy.permitAll()}; audience binding is pinned elsewhere.
     */
    @Test
    void aValidDidKeyTokenSignsInThroughTheTokenForm() {
        DidKeyTool.Minted minted = DidKeyTool.mint(null, 3600, null);
        WicketTester tester = tester(false, false);
        tester.startPage(LoginPage.class);

        FormTester form = tester.newFormTester("tokenForm");
        form.setValue("token", minted.token());
        sameOrigin(tester);
        form.submit();

        LwsSession session = sessionOf(tester);
        assertTrue(session.isSignedIn(), "a valid did:key credential must sign the caller in");
        assertEquals(minted.did(), session.getPrincipal().webId(),
                "the WebID must be the DID the credential was minted for, not anything the form said");
        tester.assertRenderedPage(BrowsePage.class);
    }

    /**
     * {@code oidcLoginEnabled()} is a pure test of two configuration strings and performs no
     * discovery, so offering the box costs nothing and asserting it needs no network.
     */
    @Test
    void theSingleSignOnBoxAppearsOnlyWhenOidcLoginIsConfigured() {
        WicketTester off = tester(p -> { });
        try {
            off.startPage(LoginPage.class);
            off.assertInvisible("oidcBox");
        } finally {
            off.destroy();
        }

        WicketTester on = tester(p -> {
            p.setProperty("lws.oidc.discovery-uri", "https://idp.example/.well-known/openid-configuration");
            p.setProperty("lws.oidc.client-id", "lws-console");
        });
        try {
            on.startPage(LoginPage.class);
            on.assertVisible("oidcBox");
            on.assertVisible("oidcBox:oidcLogin");
        } finally {
            on.destroy();
        }
    }

    /**
     * Session fixation, by the route a real user takes. {@code LwsUiTest} pins the rotation by
     * calling {@code LwsSession.signIn} directly; this drives it through the page, which is where an
     * attacker's planted cookie would actually be waiting (finding M30).
     *
     * <p>The middle assertion is the control: an ordinary second render must leave the id alone, or
     * "the id changed" would prove nothing about signing in.
     */
    @Test
    void signingInThroughTheLoginPageRotatesTheSession() {
        WicketTester tester = tester(true, false);
        tester.startPage(LoginPage.class);
        String before = tester.getSession().getId();
        assertNotNull(before, "a session must be established by the time the login page has rendered");

        tester.startPage(LoginPage.class);
        assertEquals(before, tester.getSession().getId(),
                "an ordinary request must not rotate the session");

        FormTester form = tester.newFormTester("devForm");
        form.setValue("webId", ALICE);
        sameOrigin(tester);
        form.submit();

        assertTrue(sessionOf(tester).isSignedIn());
        assertNotEquals(before, tester.getSession().getId(),
                "the session that carries the identity must not be the one the visitor arrived with");
    }
}
