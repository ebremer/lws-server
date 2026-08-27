package com.ebremer.lws.server.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Properties;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.wicket.RuntimeConfigurationType;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.wicket.settings.ExceptionSettings;
import org.apache.wicket.util.tester.FormTester;
import org.apache.wicket.util.tester.WicketTester;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.TestDirs;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.AudiencePolicy;
import com.ebremer.lws.server.auth.DidKeyValidator;
import com.ebremer.lws.server.auth.HttpDocumentLoader;
import com.ebremer.lws.server.auth.LwsCredentialValidator;
import com.ebremer.lws.server.auth.LwsOpenIdValidator;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;
import com.ebremer.lws.server.auth.SsiCidValidator;
import com.ebremer.lws.server.auth.WacAclService;
import com.ebremer.lws.server.core.IfMatch;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.ResourceRegistry;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.core.ResourceService.TypeHint;
import com.ebremer.lws.server.core.ResourceService.WriteRequest;
import com.ebremer.lws.server.core.ResourceType;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.storage.FileSystemBinaryStore;
import com.ebremer.lws.server.vocab.ACL;

/**
 * Tests the Wicket management UI with {@link WicketTester}: capability gating (anonymous vs owner
 * vs non-owner), creating a resource through the create form, and editing an ACL through the ACL
 * editor.
 *
 * @author Erich Bremer
 */
class LwsUiTest {

    /**
     * A fresh data directory per test. Deleted on the way out where the platform allows it, and by
     * the next run's sweep where it does not — see {@link TestDirs}.
     */
    private final Path tempDir = TestDirs.create();

    private static final String BASE = "http://localhost:8080";
    private static final String ROOT = BASE + "/";
    private static final String ALICE = "https://alice.example/profile#me";
    private static final String BOB = "https://bob.example/profile#me";

    private ResourceService rs;
    private WacAclService wac;
    private WicketTester tester;
    private final LwsPrincipal alice = new LwsPrincipal(ALICE, "iss", null);
    private final LwsPrincipal bob = new LwsPrincipal(BOB, "iss", null);

    @BeforeEach
    void setUp() throws Exception {
        Tdb2RdfStore store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        Path tmp = tempDir;
        FileSystemBinaryStore blobs = new FileSystemBinaryStore(tmp.resolve("blobs"));
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.access-control", "wac");
        p.setProperty("lws.owners", ALICE);
        p.setProperty("lws.public-read", "true");
        p.setProperty("lws.ui.dev-login", "true");
        LwsConfiguration config = LwsConfiguration.of(p);
        wac = new WacAclService(store, config);
        rs = new ResourceService(store, blobs, new ResourceRegistry(), wac, config, Clock.systemUTC());
        rs.ensureStorageRoot();
        wac.bootstrapRootAcl();
        OutboundFetchPolicy permitAll = OutboundFetchPolicy.permitAll();
        AudiencePolicy anyAudience = AudiencePolicy.permitAll();
        LwsCredentialValidator credentials = new LwsCredentialValidator(
                new LwsOpenIdValidator(permitAll, new HttpDocumentLoader(permitAll), anyAudience),
                new SsiCidValidator(url -> null, anyAudience, 0),
                new DidKeyValidator(anyAudience, 0), null);
        tester = new WicketTester(new LwsWebApplication(rs, config, wac, credentials));
    }

    private void signIn(LwsPrincipal who) {
        ((LwsSession) tester.getSession()).signIn(who);
    }

    /**
     * Mark the next request as a same-origin navigation, which is what a browser sends for a form
     * the console itself rendered. The CSRF (resource-isolation) listener refuses component
     * callbacks that cannot be shown to be same-origin, so a submit without this is blocked —
     * which is the whole point of {@link #crossSiteFormSubmitIsRefused()}.
     */
    private void sameOrigin() {
        // Lower-case: Wicket reads the header by this exact name and the mock request map is
        // case-sensitive, unlike a real container.
        tester.getRequest().addHeader("sec-fetch-site", "same-origin");
    }

    private void browse(String path) {
        tester.startPage(BrowsePage.class, new PageParameters().add("p", path));
        tester.assertRenderedPage(BrowsePage.class);
    }

    @Test
    void anonymousSeesNoManagementControls() {
        browse("/");
        tester.assertVisible("containerBox");          // public can read root
        tester.assertInvisible("containerBox:createForm"); // but not create
    }

    @Test
    void ownerCanCreateResourceThroughForm() {
        signIn(alice);
        browse("/");
        tester.assertVisible("containerBox:createForm");
        FormTester form = tester.newFormTester("containerBox:createForm");
        form.setValue("newName", "hello");
        form.select("newType", 1); // "RDF (Turtle)"
        form.setValue("newContent", "<#it> <http://schema.org/name> \"Hi\" .");
        sameOrigin();
        form.submit();
        assertTrue(rs.stat("/hello").isPresent(), "resource should have been created via the UI");
    }

    @Test
    void ownerCanEditAclThroughEditor() {
        signIn(alice);
        browse("/");
        tester.assertVisible("aclBox");
        FormTester form = tester.newFormTester("aclBox:aclForm");
        form.setValue("aclArea", "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n"
                + "<#a> a acl:Authorization ;\n"
                + "  acl:accessTo <" + ROOT + "> ; acl:default <" + ROOT + "> ;\n"
                + "  acl:agent <" + ALICE + "> ; acl:mode acl:Read, acl:Write, acl:Control .\n"
                + "<#b> a acl:Authorization ;\n"
                + "  acl:accessTo <" + ROOT + "> ; acl:agent <" + BOB + "> ; acl:mode acl:Read .\n");
        sameOrigin();
        form.submit();
        Model acl = wac.getAclModel(ROOT);
        assertTrue(acl.contains(null, ACL.agent, acl.createResource(BOB)),
                "ACL should now grant Bob");
    }

    @Test
    void ownerCanUploadBinaryFileThroughForm() throws Exception {
        signIn(alice);
        browse("/");
        java.io.File tmp = Files.createTempFile("upload", ".png").toFile();
        Files.write(tmp.toPath(), new byte[] {(byte) 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a});
        FormTester form = tester.newFormTester("containerBox:createForm");
        form.setValue("newName", "pic");
        form.setFile("newFile", new org.apache.wicket.util.file.File(tmp), "image/png");
        sameOrigin();
        form.submit();
        var meta = rs.stat("/pic");
        assertTrue(meta.isPresent(), "uploaded file should create a resource");
        assertEquals(ResourceType.NON_RDF_SOURCE, meta.get().type());
        assertEquals("image/png", meta.get().contentType());

        // The binary view offers a "replace with file" form to a writer.
        browse("/pic");
        tester.assertVisible("binaryBox");
        tester.assertVisible("binaryBox:replaceForm");
    }

    /**
     * The CSRF defence: a POST that a browser reports as coming from another site must not reach
     * the component callback, even though the victim is signed in and authorized. Wicket has no
     * CSRF token, so without the resource-isolation listener a cross-site page could drive any
     * console action in a signed-in user's session.
     */
    @Test
    void crossSiteFormSubmitIsRefused() {
        signIn(alice);
        browse("/");
        FormTester form = tester.newFormTester("containerBox:createForm");
        form.setValue("newName", "csrf");
        form.select("newType", 1);
        form.setValue("newContent", "<#it> <http://schema.org/name> \"nope\" .");
        tester.getRequest().addHeader("sec-fetch-site", "cross-site");
        form.submit();
        assertFalse(rs.stat("/csrf").isPresent(),
                "a cross-site form submit must not create a resource");
    }

    /**
     * Wicket's default configuration type is DEVELOPMENT, and nothing overrode it — so the shipped
     * jar rendered a full stack trace to whoever triggered an unhandled exception, anonymous or not,
     * and ran a one-second markup-polling thread for the life of the process (finding M29).
     */
    @Test
    void theConsoleRunsInDeploymentModeAndHidesStackTraces() {
        assertEquals(RuntimeConfigurationType.DEPLOYMENT, tester.getApplication().getConfigurationType());
        assertEquals(ExceptionSettings.SHOW_INTERNAL_ERROR_PAGE,
                tester.getApplication().getExceptionSettings().getUnexpectedExceptionDisplay());
    }

    /**
     * Session fixation: the session that carries the identity must not be the one an attacker could
     * have planted before sign-in, and signing out must destroy the session rather than blank a
     * field on it — the Wicket page store otherwise still holds pages rendered while signed in,
     * whose stateful callbacks remain invokable (finding M30).
     */
    @Test
    void signingInRotatesTheSessionAndSigningOutDestroysIt() {
        browse("/");                                  // establish a session while anonymous
        String before = tester.getSession().getId();

        signIn(alice);
        assertNotEquals(before, tester.getSession().getId(),
                "the session id must change when an identity is attached to it");

        LwsSession session = (LwsSession) tester.getSession();
        session.signOut();
        assertTrue(session.isSessionInvalidated() || !session.isSignedIn(),
                "signing out must invalidate the session, not just clear the principal");
        assertFalse(((LwsSession) tester.getSession()).isSignedIn());
    }

    /**
     * The console goes through the same mandatory-precondition rule as the HTTP API: it saves with
     * the entity-tag of the version it rendered, so a second editor working from a stale page is
     * refused instead of silently overwriting the first (finding M20).
     */
    @Test
    void aStaleConsoleEditIsRefusedRatherThanOverwriting() {
        rs.create("/", alice, new WriteRequest("text/turtle",
                "<#it> <http://schema.org/name> \"v1\" .".getBytes(), TypeHint.RDF_SOURCE, "notes"));
        signIn(alice);
        browse("/notes");                                    // editor one loads the page

        // Someone else changes the resource underneath it.
        rs.put("/notes", alice, new WriteRequest("text/turtle",
                "<#it> <http://schema.org/name> \"v2\" .".getBytes(), TypeHint.RDF_SOURCE, null),
                IfMatch.of("\"" + rs.stat("/notes").orElseThrow().etag() + "\""));

        FormTester form = tester.newFormTester("rdfBox:editForm");
        form.setValue("turtle", "<#it> <http://schema.org/name> \"v3\" .");
        sameOrigin();
        form.submit();

        assertTrue(rs.read("/notes", alice).rdf().toString().contains("v2"),
                "the stale save must not have landed on top of v2");
    }

    /**
     * The ACL write itself refuses a principal without Control, so a caller that forgets the check
     * — as {@code removeAcl} once did — cannot skip it (finding M11).
     */
    @Test
    void aclWritesRefuseAPrincipalWithoutControl() {
        rs.create("/", alice, new WriteRequest("text/turtle",
                "<#it> <http://schema.org/name> \"x\" .".getBytes(), TypeHint.RDF_SOURCE, "guarded"));
        String target = BASE + "/guarded";
        Model acl = wac.getAclModel(ROOT);

        assertThrows(LwsException.class, () -> wac.putAclFor(bob, target, acl));
        assertThrows(LwsException.class, () -> wac.deleteAclFor(bob, target));
    }

    @Test
    void nonOwnerSeesNoEditControls() {
        // Owner creates an RDF resource.
        rs.create("/", alice, new WriteRequest("text/turtle",
                "<#it> <http://schema.org/name> \"Hi\" .".getBytes(), TypeHint.RDF_SOURCE, "doc"));
        // Bob (authenticated, non-owner) can read it (public read) but cannot edit it.
        signIn(bob);
        browse("/doc");
        tester.assertVisible("rdfBox");
        tester.assertInvisible("rdfBox:editForm");
        tester.assertInvisible("aclBox"); // no Control either
    }
}
