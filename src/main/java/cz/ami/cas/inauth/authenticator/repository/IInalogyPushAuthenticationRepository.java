package cz.ami.cas.inauth.authenticator.repository;

import cz.ami.cas.inauth.authenticator.model.push.PendingPushAuthentication;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for managing push authentication requests.
 * This interface defines methods for storing, retrieving, updating,
 * and removing push authentication requests.
 *
 * @author Inalogy
 * @since 1.0.0
 */
public interface IInalogyPushAuthenticationRepository {

    /**
     * Bean name for the repository implementation.
     */
    String BEAN_NAME = "inalogyPushAuthenticationRepository";

    /**
     * Saves a push authentication request to the repository.
     *
     * @param authentication The authentication request to save
     */
    void save(PendingPushAuthentication authentication);

    /**
     * Finds a push authentication request by its push ID.
     *
     * @param pushId The push ID to search for
     * @return An Optional containing the authentication request if found, or empty if not found
     */
    Optional<PendingPushAuthentication> findByPushId(String pushId);

    /**
     * Finds all push authentication requests for a specific username.
     *
     * @param username The username to search for
     * @return A list of authentication requests for the specified username
     */
    List<PendingPushAuthentication> findByUsername(String username);

    /**
     * Updates the response status of a push authentication request.
     *
     * @param pushId The push ID of the authentication request to update
     * @param approved True if the request was approved, false if rejected
     */
    void updateResponse(String pushId, boolean approved);

    /**
     * Removes a push authentication request from the repository.
     *
     * @param pushId The push ID of the authentication request to remove
     * @return True if the request was found and removed, false otherwise
     */
    boolean remove(String pushId);

    /**
     * Cleans up expired authentication requests from the repository.
     *
     * @return The number of expired requests that were removed
     */
    int cleanupExpired();
}
