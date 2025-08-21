package cz.ami.cas.inauth.hazelcast.registration;

import cz.ami.cas.inauth.hazelcast.InalogyRequestMap;

/**
 * Interface for managing registration requests in a distributed map.
 * Extends the generic InalogyRequestMap interface with specific functionality for registration requests.
 * This interface provides methods for storing, retrieving, updating, and removing registration requests,
 * as well as additional functionality specific to registration operations.
 */
public interface RegistrationRequestMap extends InalogyRequestMap<InalogyRegistrationRequest> {

    /**
     * Bean name for dependency injection of registration request map implementations.
     */
    public final static String BEAN_NAME = "inalogyRegRequestMap";

    /**
     * Retrieves a registration request by its encoded secret.
     * This method allows looking up requests based on the encoded secret
     * rather than the standard request ID.
     *
     * @param encodedSecret The encoded secret to look up
     * @return The registration request associated with the given encoded secret, or null if not found
     */
    InalogyRegistrationRequest getRequestBySecret(String encodedSecret);
}
