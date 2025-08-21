package cz.ami.cas.inauth.hazelcast.mfa;

import cz.ami.cas.inauth.hazelcast.InalogyRequestMap;

/**
 * Interface for managing MFA (Multi-Factor Authentication) requests in a distributed map.
 * Extends the generic InalogyRequestMap interface with specific functionality for MFA requests.
 * This interface provides methods for storing, retrieving, updating, and removing MFA requests,
 * as well as additional functionality specific to MFA operations.
 */
public interface MfaRequestMap extends InalogyRequestMap<InalogyMfaRequest> {

    /**
     * Bean name for dependency injection of MFA request map implementations.
     */
    public final static String BEAN_NAME = "inalogyMfaRequestMap";

    /**
     * Retrieves an MFA request by its push ID.
     * This method allows looking up requests based on the push notification identifier
     * rather than the standard request ID.
     *
     * @param pushId The push notification ID to look up
     * @return The MFA request associated with the given push ID, or null if not found
     */
    InalogyMfaRequest getRequestByPushId(String pushId);

}
