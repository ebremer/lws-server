package com.ebremer.lws.server.core;

import java.util.Set;

/**
 * Decides, <em>while a resource still exists</em>, which subscribers may later be told that it was
 * deleted.
 *
 * <p>The decision cannot be made when the notification is emitted, because by then the resource and
 * its own ACL are gone — erased inside the delete's own transaction (finding H24). Asking
 * "may this subscriber read it?" afterwards resolves through container inheritance instead, which
 * hands the existence of a private child to anyone who could read its parent: its full IRI, who
 * deleted it, and when (finding H19). So the question is asked first, before the transaction opens,
 * and the answer travels on the event.
 *
 * <p>The returned set is of <strong>subscription ids</strong> rather than WebIDs, so an anonymous
 * subscription (which has no WebID) is representable and two subscriptions belonging to one
 * subscriber stay distinct. A subscription created in the window between this call and delivery is
 * absent from the set and is therefore not told — the fail-closed direction.
 *
 * <p>Implementations run outside any store transaction, so they may dereference remote documents
 * (a WAC {@code acl:agentGroup}); that is the reason this happens before the writer lock is taken
 * rather than inside it.
 *
 * @author Erich Bremer
 */
@FunctionalInterface
public interface DeleteAudience {

    /** The ids of subscriptions that both cover {@code iri} and may be told about it. */
    Set<String> subscribersAllowedToKnow(String iri);
}
