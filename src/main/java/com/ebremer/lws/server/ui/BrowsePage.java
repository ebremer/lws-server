package com.ebremer.lws.server.ui;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.vocabulary.RDF;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.form.DropDownChoice;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.TextArea;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.form.upload.FileUpload;
import org.apache.wicket.markup.html.form.upload.FileUploadField;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.markup.html.link.ExternalLink;
import org.apache.wicket.markup.html.link.Link;
import org.apache.wicket.markup.html.list.ListItem;
import org.apache.wicket.markup.html.list.ListView;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.wicket.util.lang.Bytes;
import com.ebremer.lws.server.LwsConfiguration;
import com.ebremer.lws.server.auth.WacAclService;
import com.ebremer.lws.server.core.Iris;
import com.ebremer.lws.server.core.LwsException;
import com.ebremer.lws.server.core.LwsPrincipal;
import com.ebremer.lws.server.core.LwsResource;
import com.ebremer.lws.server.core.ResourceService;
import com.ebremer.lws.server.core.ResourceService.ReadResult;
import com.ebremer.lws.server.core.ResourceService.TypeHint;
import com.ebremer.lws.server.core.ResourceService.WriteRequest;
import com.ebremer.lws.server.core.ResourceType;
import com.ebremer.lws.server.rdf.RdfIO;
import com.ebremer.lws.server.vocab.LWS;

/**
 * The storage management console: browse the hierarchy, create / edit / delete resources, and
 * edit each resource's WAC ACL. All actions run in-process against {@link ResourceService} as the
 * signed-in principal, so authorization is enforced server-side; the UI only shows actions the
 * current principal is permitted to perform.
 *
 * @author Erich Bremer
 */
public final class BrowsePage extends BasePage {

    private record Item(String name, String path, String kind) implements java.io.Serializable {
    }

    public BrowsePage(PageParameters parameters) {
        super(parameters);
        ResourceService rs = app().resources();
        LwsConfiguration cfg = app().config();
        WacAclService acl = app().aclService();
        LwsPrincipal me = principal();
        String path = parameters.get("p").toString("/");
        String iri = cfg.baseUri() + path;

        add(new Label("crumb", path));

        ReadResult rr = null;
        String error = null;
        try {
            rr = rs.read(path, me);
        } catch (LwsException e) {
            error = e.status() + " — " + e.getMessage();
        }

        boolean isContainer = rr != null && rr.meta().type() == ResourceType.CONTAINER;
        boolean isRdf = rr != null && rr.meta().type() == ResourceType.RDF_SOURCE;
        boolean isBinary = rr != null && rr.meta().type() == ResourceType.NON_RDF_SOURCE;
        boolean canWrite = rr != null && rs.canWrite(me, iri);
        boolean canAppend = isContainer && rs.canAppend(me, iri);
        boolean canControl = rr != null && acl != null && rs.canControl(me, iri);

        // ----- error -----
        WebMarkupContainer errorBox = new WebMarkupContainer("errorBox");
        errorBox.add(new Label("errorMsg", error == null ? "" : error));
        errorBox.setVisible(error != null);
        add(errorBox);

        // ----- container -----
        WebMarkupContainer containerBox = new WebMarkupContainer("containerBox");
        containerBox.setVisible(isContainer);
        containerBox.add(new Label("cpath", path));
        List<Item> items = isContainer ? children(rr.rdf(), iri, cfg) : List.of();
        final String here = path;
        containerBox.add(new ListView<Item>("items", items) {
            @Override
            protected void populateItem(ListItem<Item> li) {
                Item it = li.getModelObject();
                BookmarkablePageLink<Void> link =
                        new BookmarkablePageLink<>("link", BrowsePage.class, new PageParameters().add("p", it.path()));
                link.add(new Label("name", it.name()));
                li.add(link);
                li.add(new Label("kind", it.kind()));
                Link<Void> del = new Link<>("del") {
                    @Override
                    public void onClick() {
                        deleteAndReturn(it.path(), here);
                    }
                };
                del.setVisible(canWrite);
                li.add(del);
            }
        });
        containerBox.add(new Label("empty", "(empty container)").setVisible(items.isEmpty()));

        IModel<String> newName = Model.of("");
        IModel<String> newType = Model.of("RDF (Turtle)");
        IModel<String> newContent = Model.of("");
        FileUploadField newFile = new FileUploadField("newFile");
        Form<Void> createForm = new Form<>("createForm") {
            @Override
            protected void onSubmit() {
                create(here, newName.getObject(), newType.getObject(), newContent.getObject(),
                        newFile.getFileUploads());
            }
        };
        createForm.setMultiPart(true);
        createForm.setMaxSize(Bytes.megabytes(64));
        createForm.add(new TextField<>("newName", newName));
        createForm.add(new DropDownChoice<>("newType", newType, List.of("Container", "RDF (Turtle)", "Text")));
        createForm.add(new TextArea<>("newContent", newContent));
        createForm.add(newFile);
        createForm.setVisible(canAppend);
        containerBox.add(createForm);
        add(containerBox);

        // ----- RDF resource -----
        WebMarkupContainer rdfBox = new WebMarkupContainer("rdfBox");
        rdfBox.setVisible(isRdf);
        rdfBox.add(new Label("rpath", path));
        String turtle = isRdf ? RdfIO.writeString(rr.rdf(), RDFFormat.TURTLE_PRETTY) : "";
        rdfBox.add(new Label("rdfView", turtle).setVisible(isRdf && !canWrite));
        IModel<String> editModel = Model.of(turtle);
        Form<Void> editForm = new Form<>("editForm") {
            @Override
            protected void onSubmit() {
                putRdf(here, editModel.getObject());
            }
        };
        editForm.add(new TextArea<>("turtle", editModel));
        editForm.setVisible(canWrite);
        rdfBox.add(editForm);
        Link<Void> deleteRdf = new Link<>("deleteRdf") {
            @Override
            public void onClick() {
                deleteAndReturn(here, parentOf(here));
            }
        };
        deleteRdf.setVisible(canWrite);
        rdfBox.add(deleteRdf);
        add(rdfBox);

        // ----- binary resource -----
        WebMarkupContainer binaryBox = new WebMarkupContainer("binaryBox");
        binaryBox.setVisible(isBinary);
        binaryBox.add(new Label("bpath", path));
        binaryBox.add(new Label("ctype", isBinary ? String.valueOf(rr.meta().contentType()) : ""));
        binaryBox.add(new Label("bsize", isBinary ? String.valueOf(rr.meta().size()) : ""));
        binaryBox.add(new ExternalLink("download", iri));
        FileUploadField replaceFile = new FileUploadField("replaceFile");
        Form<Void> replaceForm = new Form<>("replaceForm") {
            @Override
            protected void onSubmit() {
                replaceBinary(here, replaceFile.getFileUploads());
            }
        };
        replaceForm.setMultiPart(true);
        replaceForm.setMaxSize(Bytes.megabytes(64));
        replaceForm.add(replaceFile);
        replaceForm.setVisible(canWrite);
        binaryBox.add(replaceForm);
        Link<Void> deleteBin = new Link<>("deleteBin") {
            @Override
            public void onClick() {
                deleteAndReturn(here, parentOf(here));
            }
        };
        deleteBin.setVisible(canWrite);
        binaryBox.add(deleteBin);
        add(binaryBox);

        // ----- ACL editor (WAC + control) -----
        WebMarkupContainer aclBox = new WebMarkupContainer("aclBox");
        aclBox.setVisible(canControl);
        final String targetIri = iri;
        String aclInitial = canControl ? aclTurtle(acl, targetIri, me) : "";
        IModel<String> aclModel = Model.of(aclInitial);
        Form<Void> aclForm = new Form<>("aclForm") {
            @Override
            protected void onSubmit() {
                saveAcl(targetIri, here, aclModel.getObject());
            }
        };
        aclForm.add(new TextArea<>("aclArea", aclModel));
        aclBox.add(aclForm);
        Link<Void> deleteAcl = new Link<>("deleteAcl") {
            @Override
            public void onClick() {
                removeAcl(targetIri, here);
            }
        };
        aclBox.add(deleteAcl);
        add(aclBox);
    }

    // ----- actions -----

    private void create(String containerPath, String name, String type, String content, List<FileUpload> files) {
        ResourceService rs = app().resources();
        LwsPrincipal me = principal();
        WriteRequest req;
        String slug = (name == null || name.isBlank()) ? null : name.trim();
        if (files != null && !files.isEmpty()) {
            // An uploaded file always creates a binary (non-RDF) resource.
            FileUpload fu = files.get(0);
            String ct = fu.getContentType() == null ? "application/octet-stream" : fu.getContentType();
            if (slug == null) {
                slug = fu.getClientFileName();
            }
            req = new WriteRequest(ct, fu.getBytes(), TypeHint.NON_RDF_SOURCE, slug);
        } else {
            byte[] body = content == null ? new byte[0] : content.getBytes(StandardCharsets.UTF_8);
            if ("Container".equals(type)) {
                req = new WriteRequest(null, new byte[0], TypeHint.CONTAINER, slug);
            } else if ("Text".equals(type)) {
                req = new WriteRequest("text/plain", body, TypeHint.NON_RDF_SOURCE, slug);
            } else {
                req = new WriteRequest("text/turtle", body, TypeHint.RDF_SOURCE, slug);
            }
        }
        try {
            LwsResource created = rs.create(containerPath, me, req);
            getSession().success("Created " + created.iri());
        } catch (LwsException | IllegalArgumentException e) {
            getSession().error("Create failed: " + e.getMessage());
        }
        setResponsePage(BrowsePage.class, new PageParameters().add("p", containerPath));
    }

    private void putRdf(String path, String turtle) {
        ResourceService rs = app().resources();
        LwsPrincipal me = principal();
        try {
            rs.put(path, me, new WriteRequest("text/turtle",
                    turtle == null ? new byte[0] : turtle.getBytes(StandardCharsets.UTF_8),
                    TypeHint.RDF_SOURCE, null));
            getSession().success("Saved.");
        } catch (LwsException | IllegalArgumentException e) {
            getSession().error("Save failed: " + e.getMessage());
        }
        setResponsePage(BrowsePage.class, new PageParameters().add("p", path));
    }

    private void replaceBinary(String path, List<FileUpload> files) {
        ResourceService rs = app().resources();
        LwsPrincipal me = principal();
        if (files == null || files.isEmpty()) {
            getSession().error("Choose a file to upload.");
        } else {
            FileUpload fu = files.get(0);
            String ct = fu.getContentType() == null ? "application/octet-stream" : fu.getContentType();
            try {
                rs.put(path, me, new WriteRequest(ct, fu.getBytes(), TypeHint.NON_RDF_SOURCE, null));
                getSession().success("Replaced content.");
            } catch (LwsException | IllegalArgumentException e) {
                getSession().error("Replace failed: " + e.getMessage());
            }
        }
        setResponsePage(BrowsePage.class, new PageParameters().add("p", path));
    }

    private void deleteAndReturn(String path, String returnPath) {
        ResourceService rs = app().resources();
        LwsPrincipal me = principal();
        try {
            rs.delete(path, me);
            getSession().success("Deleted " + path);
        } catch (LwsException e) {
            getSession().error("Delete failed: " + e.getMessage());
        }
        setResponsePage(BrowsePage.class, new PageParameters().add("p", returnPath));
    }

    private void saveAcl(String targetIri, String returnPath, String turtle) {
        ResourceService rs = app().resources();
        WacAclService acl = app().aclService();
        LwsPrincipal me = principal();
        try {
            if (!rs.canControl(me, targetIri)) {
                getSession().error("You do not have Control permission on this resource.");
            } else {
                org.apache.jena.rdf.model.Model model = RdfIO.parse(
                        turtle == null ? new byte[0] : turtle.getBytes(StandardCharsets.UTF_8),
                        Lang.TURTLE, targetIri);
                acl.putAclFor(targetIri, model);
                getSession().success("ACL saved.");
            }
        } catch (IllegalArgumentException e) {
            getSession().error("Invalid ACL: " + e.getMessage());
        }
        setResponsePage(BrowsePage.class, new PageParameters().add("p", returnPath));
    }

    private void removeAcl(String targetIri, String returnPath) {
        WacAclService acl = app().aclService();
        if (acl != null && !Iris.isRoot(toPath(targetIri, app().config()))) {
            acl.deleteAclFor(targetIri);
            getSession().success("ACL removed.");
        } else {
            getSession().error("The root ACL cannot be removed.");
        }
        setResponsePage(BrowsePage.class, new PageParameters().add("p", returnPath));
    }

    // ----- helpers -----

    private static List<Item> children(org.apache.jena.rdf.model.Model model, String containerIri, LwsConfiguration cfg) {
        List<Item> out = new ArrayList<>();
        Resource container = model.getResource(containerIri);
        for (RDFNode node : model.listObjectsOfProperty(container, LWS.items).toList()) {
            if (!node.isResource()) {
                continue;
            }
            String childIri = node.asResource().getURI();
            String childPath = Iris.toPath(cfg.baseUri(), childIri);
            if (childPath == null) {
                continue;
            }
            boolean isC = model.contains(node.asResource(), RDF.type, LWS.Container);
            String name = Iris.lastSegment(childPath) + (Iris.isContainerPath(childPath) ? "/" : "");
            out.add(new Item(name, childPath, isC ? "container" : "resource"));
        }
        out.sort((a, b) -> a.name().compareToIgnoreCase(b.name()));
        return out;
    }

    private static String aclTurtle(WacAclService acl, String targetIri, LwsPrincipal me) {
        org.apache.jena.rdf.model.Model model = acl.getAclModel(targetIri);
        if (!model.isEmpty()) {
            return RdfIO.writeString(model, RDFFormat.TURTLE_PRETTY);
        }
        String webId = me == null ? "https://example.org/profile#me" : me.webId();
        return "@prefix acl:  <http://www.w3.org/ns/auth/acl#> .\n"
                + "@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\n"
                + "<#owner> a acl:Authorization ;\n"
                + "    acl:accessTo <" + targetIri + "> ;\n"
                + "    acl:default  <" + targetIri + "> ;   # applies to contained resources (containers only)\n"
                + "    acl:agent    <" + webId + "> ;\n"
                + "    acl:mode     acl:Read, acl:Write, acl:Control .\n\n"
                + "# Example: let anyone read --\n"
                + "# <#public> a acl:Authorization ;\n"
                + "#     acl:accessTo <" + targetIri + "> ;\n"
                + "#     acl:agentClass foaf:Agent ;\n"
                + "#     acl:mode acl:Read .\n";
    }

    private String parentOf(String path) {
        String parent = Iris.parentPath(path);
        return parent == null ? "/" : parent;
    }

    private static String toPath(String iri, LwsConfiguration cfg) {
        String p = Iris.toPath(cfg.baseUri(), iri);
        return p == null ? "/" : p;
    }
}
