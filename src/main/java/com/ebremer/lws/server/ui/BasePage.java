package com.ebremer.lws.server.ui;

import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.markup.html.link.Link;
import org.apache.wicket.markup.html.panel.FeedbackPanel;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import com.ebremer.lws.server.core.LwsPrincipal;

/**
 * Common page chrome (sign-in status bar + feedback) shared via Wicket markup inheritance.
 *
 * @author Erich Bremer
 */
public abstract class BasePage extends WebPage {

    protected BasePage(PageParameters parameters) {
        super(parameters);
        buildChrome();
    }

    protected BasePage() {
        buildChrome();
    }

    private void buildChrome() {
        LwsSession session = LwsSession.get();
        add(new BookmarkablePageLink<Void>("home", BrowsePage.class));
        add(new Label("principal", session.isSignedIn() ? session.getPrincipal().webId() : "anonymous"));
        add(new BookmarkablePageLink<Void>("signin", LoginPage.class).setVisible(!session.isSignedIn()));
        Link<Void> signout = new Link<>("signout") {
            @Override
            public void onClick() {
                LwsSession.get().signOut();
                getSession().info("Signed out.");
                setResponsePage(BrowsePage.class);
            }
        };
        signout.setVisible(session.isSignedIn());
        add(signout);
        add(new FeedbackPanel("feedback"));
    }

    protected LwsWebApplication app() {
        return LwsWebApplication.instance();
    }

    protected LwsPrincipal principal() {
        return LwsSession.get().getPrincipal();
    }
}
