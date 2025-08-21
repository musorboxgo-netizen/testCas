package cz.ami.cas.inauth.hazelcast.registration;

import com.hazelcast.config.MapConfig;
import com.hazelcast.config.NamedConfig;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import cz.ami.cas.inauth.hazelcast.InalogyRequestMap;
import cz.ami.cas.inauth.hazelcast.mfa.InalogyMfaRequest;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.hz.HazelcastConfigurationFactory;

import java.util.concurrent.TimeUnit;

/**
 * Implementation of registration request management using Hazelcast distributed maps.
 * This class provides functionality for storing, retrieving, updating, and removing
 * registration requests in a distributed environment.
 */
@Slf4j
public class InalogyRegRequestHazelcastMap implements RegistrationRequestMap {

    /**
     * Name of the Hazelcast map that stores registration requests.
     */
    private final static String REQUEST_MAP_NAME = "InalogyRegRequest";

    /**
     * Name of the Hazelcast map that stores mappings between encoded secrets and request IDs.
     */
    private final static String KEY_MAP_NAME = "InalogySecretMap";

    /**
     * Hazelcast distributed map that stores registration requests with request ID as the key.
     */
    private final IMap<String, InalogyRegistrationRequest> regRequestMap;

    /**
     * Hazelcast distributed map that stores mappings between encoded secrets and request IDs.
     */
    private final IMap<String, String> secretMap;

    /**
     * Constructor for creating a new InalogyRegRequestHazelcastMap.
     * Initializes two Hazelcast distributed maps:
     * 1. regRequestMap - for storing registration requests
     * 2. secretMap - for mapping encoded secrets to request IDs
     *
     * @param hazelcastInstance The Hazelcast instance to use for creating distributed maps
     * @param casProperties CAS configuration properties
     * @param mfaProperties MFA-specific configuration properties including timeout settings
     */
    public InalogyRegRequestHazelcastMap(final HazelcastInstance hazelcastInstance, final CasConfigurationProperties casProperties, CoreInalogyMultifactorProperties mfaProperties) {

        LOGGER.debug("Creating Hazelcast Map [{}]", REQUEST_MAP_NAME);

        NamedConfig requestMapConfig = HazelcastConfigurationFactory.buildMapConfig(casProperties.getTicket().getRegistry().getHazelcast(), REQUEST_MAP_NAME, TimeUnit.MILLISECONDS.toSeconds(mfaProperties.getTimeoutMs()) + 2);
        hazelcastInstance.getConfig().addMapConfig((MapConfig) requestMapConfig);
        regRequestMap = hazelcastInstance.getMap(REQUEST_MAP_NAME);

        NamedConfig secretMapConfig = HazelcastConfigurationFactory.buildMapConfig(casProperties.getTicket().getRegistry().getHazelcast(), KEY_MAP_NAME, TimeUnit.MILLISECONDS.toSeconds(mfaProperties.getTimeoutMs()) + 2);
        hazelcastInstance.getConfig().addMapConfig((MapConfig) secretMapConfig);
        secretMap = hazelcastInstance.getMap(KEY_MAP_NAME);
    }

    /**
     * Retrieves a registration request by its request ID.
     *
     * @param requestId The ID of the request to retrieve
     * @return The registration request associated with the given request ID, or null if not found
     */
    @Override
    public InalogyRegistrationRequest getRequest(String requestId) {
        return regRequestMap.get(requestId);
    }

    /**
     * Stores a registration request in the distributed map and creates a mapping between
     * the encoded secret and request ID.
     *
     * @param request The registration request to store
     */
    @Override
    public void putRequest(InalogyRegistrationRequest request) {
        regRequestMap.put(request.getRequestId(), request);
        secretMap.put(request.getEncodedSecret(), request.getRequestId());
    }

    /**
     * Updates an existing registration request by removing the old one and adding the updated one.
     *
     * @param requestId The ID of the request to update
     * @param request The updated registration request
     */
    @Override
    public void updateRequest(String requestId, InalogyRegistrationRequest request) {
        regRequestMap.remove(requestId);
        putRequest(request);
    }

    /**
     * Checks if a registration request with the given request ID exists.
     *
     * @param requestId The request ID to check
     * @return true if the request exists, false otherwise
     */
    @Override
    public boolean containsKey(String requestId) {
        return regRequestMap.containsKey(requestId);
    }

    /**
     * Removes a registration request and its associated secret mapping.
     *
     * @param requestId The ID of the request to remove
     */
    @Override
    public void removeRequest(String requestId) {
        regRequestMap.remove(requestId);
        secretMap.remove(requestId);
    }

    /**
     * Marks a registration request as rejected.
     * This implementation is empty as registration requests may not have a rejection state.
     *
     * @param request The registration request to reject
     */
    @Override
    public void reject(InalogyRegistrationRequest request) {
        // Implementation is empty as registration requests may not have a rejection state
    }

    /**
     * Retrieves a registration request by its encoded secret.
     * First looks up the request ID associated with the encoded secret,
     * then retrieves the registration request using that request ID.
     *
     * @param encodedSecret The encoded secret to look up
     * @return The registration request associated with the given encoded secret, or null if not found
     */
    @Override
    public InalogyRegistrationRequest getRequestBySecret(String encodedSecret) {
        var requestId = secretMap.get(encodedSecret);
        if (requestId == null) {
            return null;
        }
        return regRequestMap.get(requestId);
    }
}
