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

@Slf4j
public class InalogyMfaRequestHazelcastMap implements MfaRequestMap {

    private final static String REQUEST_MAP_NAME = "InalogyMfaRequest";

    private final static String PUSH_ID_MAP_NAME = "InalogyPushIdMap";

    private final IMap<String, InalogyMfaRequest> mfaRequestMap;

    private final IMap<String, String> pushIdMap;

    private final CoreInalogyMultifactorProperties mfaProperties;

    public InalogyMfaRequestHazelcastMap(final HazelcastInstance hazelcastInstance, final CasConfigurationProperties casProperties) {
        this.mfaProperties = casProperties.getAuthn().getMfa().getInalogy().getCore();

        LOGGER.debug("Creating Hazelcast Map [{}]", REQUEST_MAP_NAME);

        NamedConfig requestMapConfig = HazelcastConfigurationFactory.buildMapConfig(casProperties.getTicket().getRegistry().getHazelcast(), REQUEST_MAP_NAME, mfaProperties.getTimeoutMs());
        hazelcastInstance.getConfig().addMapConfig((MapConfig) requestMapConfig);
        mfaRequestMap = hazelcastInstance.getMap(REQUEST_MAP_NAME);

        NamedConfig pushIdMapConfig = HazelcastConfigurationFactory.buildMapConfig(casProperties.getTicket().getRegistry().getHazelcast(), PUSH_ID_MAP_NAME, mfaProperties.getTimeoutMs());
        hazelcastInstance.getConfig().addMapConfig((MapConfig) pushIdMapConfig);
        pushIdMap = hazelcastInstance.getMap(PUSH_ID_MAP_NAME);
    }

    @Override
    public InalogyMfaRequest getRequest(String requestId) {
        return mfaRequestMap.get(requestId);
    }

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

    @Override
    public boolean containsKey(String requestId) {
        return mfaRequestMap.containsKey(requestId);
    }

    @Override
    public InalogyMfaRequest getRequestByPushId(String pushId) {
        var requestId = pushIdMap.get(pushId);
        if (requestId == null) {
            return null;
        }
        return mfaRequestMap.get(requestId);
    }

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

    @Override
    public void reject(InalogyMfaRequest pendingRequest) {
        pendingRequest.setStatus(REJECTED);
        updateRequest(pendingRequest.getRequestId(), pendingRequest);
    }
}
