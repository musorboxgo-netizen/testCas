package cz.ami.cas.inauth.hazelcast.mfa;

import com.hazelcast.config.MapConfig;
import com.hazelcast.config.NamedConfig;
import com.hazelcast.map.IMap;
import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import cz.ami.cas.inauth.hazelcast.InalogyRequestMap;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.configuration.CasConfigurationProperties;

import java.util.concurrent.TimeUnit;
import com.hazelcast.core.HazelcastInstance;
import org.apereo.cas.hz.HazelcastConfigurationFactory;

import static cz.ami.cas.inauth.authenticator.model.push.PushAuthenticationStatus.REJECTED;

/**
 * Implementation of MFA request management using Hazelcast distributed maps.
 * This class provides functionality for storing, retrieving, updating, and removing
 * MFA (Multi-Factor Authentication) requests in a distributed environment.
 */
@Slf4j
public class InalogyMfaRequestHazelcastMap implements MfaRequestMap {

    /**
     * Name of the Hazelcast map that stores MFA requests.
     */
    private final static String REQUEST_MAP_NAME = "InalogyMfaRequest";

    /**
     * Name of the Hazelcast map that stores mappings between push IDs and request IDs.
     */
    private final static String PUSH_ID_MAP_NAME = "InalogyPushIdMap";

    /**
     * Hazelcast distributed map that stores MFA requests with request ID as the key.
     */
    private final IMap<String, InalogyMfaRequest> mfaRequestMap;

    /**
     * Hazelcast distributed map that stores mappings between push IDs and request IDs.
     */
    private final IMap<String, String> pushIdMap;

    /**
     * Constructor for creating a new InalogyMfaRequestHazelcastMap.
     * Initializes two Hazelcast distributed maps:
     * 1. mfaRequestMap - for storing MFA requests
     * 2. pushIdMap - for mapping push IDs to request IDs
     *
     * @param hazelcastInstance The Hazelcast instance to use for creating distributed maps
     * @param casProperties CAS configuration properties
     * @param mfaProperties MFA-specific configuration properties including timeout settings
     */
    public InalogyMfaRequestHazelcastMap(final HazelcastInstance hazelcastInstance, final CasConfigurationProperties casProperties, final CoreInalogyMultifactorProperties mfaProperties) {
        LOGGER.debug("Creating Hazelcast Map [{}]", REQUEST_MAP_NAME);

        NamedConfig requestMapConfig = HazelcastConfigurationFactory.buildMapConfig(casProperties.getTicket().getRegistry().getHazelcast(), REQUEST_MAP_NAME, mfaProperties.getTimeoutMs());
        hazelcastInstance.getConfig().addMapConfig((MapConfig) requestMapConfig);
        mfaRequestMap = hazelcastInstance.getMap(REQUEST_MAP_NAME);

        NamedConfig pushIdMapConfig = HazelcastConfigurationFactory.buildMapConfig(casProperties.getTicket().getRegistry().getHazelcast(), PUSH_ID_MAP_NAME, mfaProperties.getTimeoutMs());
        hazelcastInstance.getConfig().addMapConfig((MapConfig) pushIdMapConfig);
        pushIdMap = hazelcastInstance.getMap(PUSH_ID_MAP_NAME);
    }

    /**
     * Retrieves an MFA request by its request ID.
     *
     * @param requestId The ID of the request to retrieve
     * @return The MFA request associated with the given request ID, or null if not found
     */
    @Override
    public InalogyMfaRequest getRequest(String requestId) {
        return mfaRequestMap.get(requestId);
    }

    /**
     * Stores an MFA request in the distributed map and creates a mapping between
     * the push ID and request ID. Uses locking to ensure thread safety.
     *
     * @param request The MFA request to store
     */
    @Override
    public void putRequest(InalogyMfaRequest request) {
        String pushId = request.getPushId();

        pushIdMap.lock(pushId);
        try {
            mfaRequestMap.put(request.getRequestId(), request);
            pushIdMap.put(pushId, request.getRequestId());
        } finally {
            pushIdMap.unlock(pushId);
        }
    }

    /**
     * Updates an existing MFA request by removing the old one and adding the updated one.
     * Uses locking to ensure thread safety.
     *
     * @param requestId The ID of the request to update
     * @param request The updated MFA request
     */
    @Override
    public void updateRequest(String requestId, InalogyMfaRequest request) {
        String pushId = request.getPushId();

        pushIdMap.lock(pushId);
        try {
            mfaRequestMap.remove(requestId);
            putRequest(request);
        } finally {
            pushIdMap.unlock(pushId);
        }
    }

    /**
     * Checks if an MFA request with the given request ID exists.
     *
     * @param requestId The request ID to check
     * @return true if the request exists, false otherwise
     */
    @Override
    public boolean containsKey(String requestId) {
        return mfaRequestMap.containsKey(requestId);
    }

    /**
     * Retrieves an MFA request by its push ID.
     * First looks up the request ID associated with the push ID,
     * then retrieves the MFA request using that request ID.
     *
     * @param pushId The push ID to look up
     * @return The MFA request associated with the given push ID, or null if not found
     */
    @Override
    public InalogyMfaRequest getRequestByPushId(String pushId) {
        var requestId = pushIdMap.get(pushId);
        if (requestId == null) {
            return null;
        }
        return mfaRequestMap.get(requestId);
    }

    /**
     * Removes an MFA request and its associated push ID mapping.
     * Uses locking to ensure thread safety when removing the push ID mapping.
     *
     * @param requestId The ID of the request to remove
     */
    @Override
    public void removeRequest(String requestId) {
        InalogyMfaRequest removed = mfaRequestMap.remove(requestId);
        if (removed != null) {
            String pushId = removed.getPushId();
            pushIdMap.lock(pushId);
            try {
                pushIdMap.remove(pushId, requestId);
            } finally {
                pushIdMap.unlock(pushId);
            }
        }
    }

    /**
     * Marks an MFA request as rejected and updates it in the distributed map.
     *
     * @param pendingRequest The MFA request to reject
     */
    @Override
    public void reject(InalogyMfaRequest pendingRequest) {
        pendingRequest.setStatus(REJECTED);
        updateRequest(pendingRequest.getRequestId(), pendingRequest);
    }
}
