package com.ebremer.lws.server.core;

/**
 * Callback for resource changes. Implemented by the notification subsystem and registered with
 * the {@link ResourceService}. Kept in the core package so the service does not depend on the
 * notifications package (the dependency points the other way).
 *
 * @author Erich Bremer
 */
@FunctionalInterface
public interface ResourceEventListener {

    void onResourceEvent(ResourceEvent event);
}
