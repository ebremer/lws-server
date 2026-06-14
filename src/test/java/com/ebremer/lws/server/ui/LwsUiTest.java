package com.ebremer.lws.server.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Properties;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.wicket.util.tester.FormTester;
import org.apache.wicket.util.tester.WicketTester;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.DidKeyValidator;
import com.ebremer.lws.server.auth.LwsCredentialValidator;
import com.ebremer.lws.server.auth.LwsOpenIdValidator;
import com.ebremer.lws.server.auth.OutboundFetchPolicy;
import com.ebremer.lws.server.auth.SsiCidValidator;
import com.ebremer.lws.server.auth.WacAclService;
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
        Path tmp = Files.createTempDirectory("lws-ui-test");
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
        LwsCredentialValidator credentials = new LwsCredentialValidator(
                new LwsOpenIdValidator(OutboundFetchPolicy.permitAll()),
                new SsiCidValidator(url -> null), new DidKeyValidator(), null);
        tester = new WicketTester(new LwsWebApplication(rs, config, wac, credentials));
    }

    private void signIn(LwsPrincipal who) {
        ((LwsSession) tester.getSession()).signIn(who);
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
