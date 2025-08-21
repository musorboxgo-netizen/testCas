package cz.ami.cas.inauth.hazelcast;

/**
 * Generic interface for managing request objects in a distributed map.
 * This interface defines the basic operations for storing, retrieving,
 * updating, and removing request objects identified by a request ID.
 *
 * @param <T> The type of request object to be managed
 */
public interface InalogyRequestMap<T> {

    /**
     * Bean name for dependency injection.
     */
    final static String BEAN_NAME = "inalogyRequestMap";

    /**
     * Retrieves a request by its ID.
     *
     * @param requestId The ID of the request to retrieve
     * @return The request object associated with the given ID, or null if not found
     */
    T getRequest(String requestId);

    /**
     * Stores a request in the map.
     *
     * @param request The request object to store
     */
    void putRequest(T request);

    /**
     * Updates an existing request with new data.
     *
     * @param requestId The ID of the request to update
     * @param request The updated request object
     */
    void updateRequest(String requestId, T request);

    /**
     * Removes a request from the map.
     *
     * @param requestId The ID of the request to remove
     */
    void removeRequest(String requestId);

    /**
     * Checks if a request with the given ID exists in the map.
     *
     * @param requestId The request ID to check
     * @return true if the request exists, false otherwise
     */
    boolean containsKey(String requestId);

    /**
     * Marks a request as rejected.
     *
     * @param request The request to reject
     */
    void reject(T request);
}
