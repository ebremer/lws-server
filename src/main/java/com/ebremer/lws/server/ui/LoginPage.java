package com.ebremer.lws.server.ui;

import java.util.Optional;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.TextArea;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.link.ExternalLink;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Sign-in page. Two mechanisms:
 * <ul>
 *   <li><b>ID token</b> (always available): paste an OpenID Connect ID token, validated by the
 *       same {@code LwsOpenIdValidator} the HTTP API uses.</li>
 *   <li><b>Developer sign-in</b> (only when {@code lws.ui.dev-login=true}): act as any WebID —
 *       impersonation, for development/administration only.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class LoginPage extends BasePage {

    public LoginPage() {
        boolean devEnabled = app().config().uiDevLoginEnabled();

        IModel<String> webId = Model.of("");
        Form<Void> devForm = new Form<>("devForm") {
            @Override
            protected void onSubmit() {
                String w = webId.getObject() == null ? "" : webId.getObject().trim();
                if (w.isEmpty()) {
                    LwsSession.get().signOut();
                    getSession().info("Now browsing anonymously.");
                } else {
                    LwsSession.get().signIn(new LwsPrincipal(w, "urn:lws:dev-login", null));
                    getSession().success("Signed in as " + w);
                }
                setResponsePage(BrowsePage.class);
            }
        };
        devForm.add(new TextField<>("webId", webId));
        devForm.setVisible(devEnabled);
        add(devForm);
        add(new Label("devDisabled",
                "Developer sign-in is disabled. Set lws.ui.dev-login=true to enable it (development only).")
                .setVisible(!devEnabled));

        IModel<String> token = Model.of("");
        Form<Void> tokenForm = new Form<>("tokenForm") {
            @Override
            protected void onSubmit() {
                String t = token.getObject() == null ? "" : token.getObject().trim();
                if (t.isEmpty()) {
                    getSession().error("Paste an ID token.");
                    setResponsePage(LoginPage.class);
                    return;
                }
                Optional<LwsPrincipal> p = app().validator().validate(t);
                if (p.isEmpty()) {
                    getSession().error("Token rejected (invalid/expired, or issuer not trusted by the subject).");
                    setResponsePage(LoginPage.class);
                    return;
                }
                LwsSession.get().signIn(p.get());
                getSession().success("Signed in as " + p.get().webId());
                setResponsePage(BrowsePage.class);
            }
        };
        tokenForm.add(new TextArea<>("token", token));
        add(tokenForm);

        WebMarkupContainer oidcBox = new WebMarkupContainer("oidcBox");
        oidcBox.setVisible(app().config().oidcLoginEnabled());
        oidcBox.add(new ExternalLink("oidcLogin", "oidc-login"));
        add(oidcBox);
    }
}
