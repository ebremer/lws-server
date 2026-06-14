package com.ebremer.lws.server.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Properties;
import org.apache.jena.query.DatasetFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.core.AclMode;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.RequestContext;
import com.ebremer.lws.server.rdf.Tdb2RdfStore;
import com.ebremer.lws.server.vocab.ACL;
import com.ebremer.lws.server.vocab.VCARD;
import com.ebremer.lws.server.vocab.FOAF;

/**
 * Unit tests for the Web Access Control engine: owner control, public vs authenticated access,
 * per-agent grants, container inheritance via {@code acl:default}, and nearest-ACL override.
 *
 * @author Erich Bremer
 */
class WacAclServiceTest {

    private static final String BASE = "http://localhost:8080";
    private static final String ROOT = BASE + "/";
    private static final String SHARED = BASE + "/shared/";
    private static final String MEMBERS = BASE + "/members/";

    private static final String ALICE = "https://alice.example/profile#me"; // storage owner
    private static final String BOB = "https://bob.example/profile#me";
    private static final String CAROL = "https://carol.example/profile#me";

    private WacAclService wac;
    private Tdb2RdfStore store;
    private final LwsPrincipal alice = new LwsPrincipal(ALICE, "iss", null);
    private final LwsPrincipal bob = new LwsPrincipal(BOB, "iss", null);
    private final LwsPrincipal carol = new LwsPrincipal(CAROL, "iss", null);

    @BeforeEach
    void setUp() {
        store = new Tdb2RdfStore(DatasetFactory.createTxnMem());
        Properties p = new Properties();
        p.setProperty("lws.base-uri", BASE);
        p.setProperty("lws.access-control", "wac");
        p.setProperty("lws.owners", ALICE);
        p.setProperty("lws.public-read", "true");
        LwsConfiguration config = LwsConfiguration.of(p);
        wac = new WacAclService(store, config);
        wac.bootstrapRootAcl();
    }

    @Test
    void ownerHasFullControlEverywhereByInheritance() {
        assertTrue(wac.allows(alice, ROOT, AclMode.READ));
        assertTrue(wac.allows(alice, ROOT, AclMode.WRITE));
        assertTrue(wac.allows(alice, ROOT, AclMode.CONTROL));
        // inherited down the tree
        assertTrue(wac.allows(alice, BASE + "/anything/deep/x", AclMode.WRITE));
        assertTrue(wac.allows(alice, BASE + "/anything/deep/x", AclMode.CONTROL));
    }

    @Test
    void publicReadButNotWriteAtRoot() {
        assertTrue(wac.allows(null, ROOT, AclMode.READ));
        assertFalse(wac.allows(null, ROOT, AclMode.WRITE));
        assertFalse(wac.allows(null, ROOT, AclMode.CONTROL));
    }

    @Test
    void nonOwnerGetsOnlyPublicAccessByDefault() {
        assertTrue(wac.allows(bob, ROOT, AclMode.READ));   // public read
        assertFalse(wac.allows(bob, ROOT, AclMode.WRITE)); // no write granted
    }

    @Test
    void perAgentGrantWithContainerInheritance() {
        // Owner grants Bob read+write over /shared/ and everything beneath it.
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(SHARED));
        a.addProperty(ACL.defaultAccess, acl.createResource(SHARED));
        a.addProperty(ACL.agent, acl.createResource(BOB));
        a.addProperty(ACL.mode, ACL.Read);
        a.addProperty(ACL.mode, ACL.Write);
        wac.putAclFor(SHARED, acl);

        assertTrue(wac.allows(bob, SHARED, AclMode.WRITE));
        assertTrue(wac.allows(bob, SHARED, AclMode.APPEND));          // Write implies Append
        assertTrue(wac.allows(bob, SHARED + "doc", AclMode.WRITE));   // inherited
        assertTrue(wac.allows(bob, SHARED + "deep/nested/x", AclMode.WRITE)); // deep inheritance

        // Carol (another user) gets nothing here.
        assertFalse(wac.allows(carol, SHARED + "doc", AclMode.WRITE));
        assertFalse(wac.allows(carol, SHARED + "doc", AclMode.READ));

        // The nearest ACL (/shared/) overrides the root: it grants no public read,
        // so the public cannot read inside /shared/ even though root allows public read.
        assertFalse(wac.allows(null, SHARED + "doc", AclMode.READ));
        assertTrue(wac.allows(null, ROOT, AclMode.READ));

        // WAC has no "super-owner": because /shared/ has its own ACL that omits Alice, the root's
        // owner grant no longer applies within /shared/ (nearest ACL wins). Alice would need to
        // include herself in /shared/'s ACL to retain access to this subtree.
        assertFalse(wac.allows(alice, SHARED + "doc", AclMode.WRITE));
    }

    @Test
    void authenticatedAgentClass() {
        // Any authenticated agent may read /members/, but the public may not.
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(MEMBERS));
        a.addProperty(ACL.defaultAccess, acl.createResource(MEMBERS));
        a.addProperty(ACL.agentClass, ACL.AuthenticatedAgent);
        a.addProperty(ACL.mode, ACL.Read);
        wac.putAclFor(MEMBERS, acl);

        assertTrue(wac.allows(bob, MEMBERS + "notice", AclMode.READ));
        assertTrue(wac.allows(carol, MEMBERS + "notice", AclMode.READ));
        assertFalse(wac.allows(null, MEMBERS + "notice", AclMode.READ)); // anonymous excluded
        assertFalse(wac.allows(bob, MEMBERS + "notice", AclMode.WRITE)); // read-only grant
    }

    @Test
    void publicAgentClassGrantsEveryone() {
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(BASE + "/public-note"));
        a.addProperty(ACL.agentClass, FOAF.Agent);
        a.addProperty(ACL.mode, ACL.Read);
        wac.putAclFor(BASE + "/public-note", acl);

        assertTrue(wac.allows(null, BASE + "/public-note", AclMode.READ));
        assertTrue(wac.allows(carol, BASE + "/public-note", AclMode.READ));
    }

    @Test
    void originRestrictedAuthorization() {
        // Bob may write /app/ only from the trusted application origin.
        String appDir = BASE + "/app/";
        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(appDir));
        a.addProperty(ACL.defaultAccess, acl.createResource(appDir));
        a.addProperty(ACL.agent, acl.createResource(BOB));
        a.addProperty(ACL.origin, acl.createResource("https://app.example"));
        a.addProperty(ACL.mode, ACL.Read);
        a.addProperty(ACL.mode, ACL.Write);
        wac.putAclFor(appDir, acl);
        try {
            RequestContext.setOrigin("https://app.example");
            assertTrue(wac.allows(bob, appDir + "doc", AclMode.WRITE));   // matching Origin
            // A non-origin-restricted authorization (public read at the root) still applies.
            assertTrue(wac.allows(null, ROOT, AclMode.READ));

            RequestContext.setOrigin("https://evil.example");
            assertFalse(wac.allows(bob, appDir + "doc", AclMode.WRITE));  // wrong Origin

            RequestContext.clear();
            assertFalse(wac.allows(bob, appDir + "doc", AclMode.WRITE));  // no Origin header at all
        } finally {
            RequestContext.clear();
        }
    }

    @Test
    void agentGroupMembership() {
        String group = BASE + "/groups/team";
        // Store the group document locally: <group> vcard:hasMember <bob>.
        org.apache.jena.rdf.model.Model groupDoc = ModelFactory.createDefaultModel();
        groupDoc.createResource(group).addProperty(VCARD.hasMember, groupDoc.createResource(BOB));
        store.writeDo(conn -> conn.put(group, groupDoc));

        Model acl = ModelFactory.createDefaultModel();
        Resource a = acl.createResource();
        a.addProperty(RDF.type, ACL.Authorization);
        a.addProperty(ACL.accessTo, acl.createResource(SHARED));
        a.addProperty(ACL.defaultAccess, acl.createResource(SHARED));
        a.addProperty(ACL.agentGroup, acl.createResource(group));
        a.addProperty(ACL.mode, ACL.Read);
        a.addProperty(ACL.mode, ACL.Write);
        wac.putAclFor(SHARED, acl);

        assertTrue(wac.allows(bob, SHARED + "doc", AclMode.WRITE));    // member of the group
        assertFalse(wac.allows(carol, SHARED + "doc", AclMode.WRITE)); // not a member
        assertFalse(wac.allows(null, SHARED + "doc", AclMode.READ));   // anonymous is not a member
    }
}
