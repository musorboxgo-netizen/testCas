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

@Slf4j
public class InalogyRegRequestHazelcastMap implements RegistrationRequestMap {

    private final static String REQUEST_MAP_NAME = "InalogyRegRequest";

    private final static String KEY_MAP_NAME = "InalogySecretMap";

    private final IMap<String, InalogyRegistrationRequest> regRequestMap;
    
    private final IMap<String, String> secretMap;
    
    private final CoreInalogyMultifactorProperties mfaProperties;

    public InalogyRegRequestHazelcastMap(final HazelcastInstance hazelcastInstance, final CasConfigurationProperties casProperties) {
        this.mfaProperties = casProperties.getAuthn().getMfa().getInalogy().getCore();

        LOGGER.debug("Creating Hazelcast Map [{}]", REQUEST_MAP_NAME);

        NamedConfig requestMapConfig = HazelcastConfigurationFactory.buildMapConfig(casProperties.getTicket().getRegistry().getHazelcast(), REQUEST_MAP_NAME, TimeUnit.MILLISECONDS.toSeconds(mfaProperties.getTimeoutMs()) + 2);
        hazelcastInstance.getConfig().addMapConfig((MapConfig) requestMapConfig);
        regRequestMap = hazelcastInstance.getMap(REQUEST_MAP_NAME);

        NamedConfig secretMapConfig = HazelcastConfigurationFactory.buildMapConfig(casProperties.getTicket().getRegistry().getHazelcast(), KEY_MAP_NAME, TimeUnit.MILLISECONDS.toSeconds(mfaProperties.getTimeoutMs()) + 2);
        hazelcastInstance.getConfig().addMapConfig((MapConfig) secretMapConfig);
        secretMap = hazelcastInstance.getMap(KEY_MAP_NAME);
    }

    @Override
    public InalogyRegistrationRequest getRequest(String requestId) {
        return regRequestMap.get(requestId);
    }

    @Override
    public void putRequest(InalogyRegistrationRequest request) {
        regRequestMap.put(request.getRequestId(), request, mfaProperties.getTimeoutMs(), TimeUnit.MILLISECONDS);
        secretMap.put(request.getEncodedSecret(), request.getRequestId(), mfaProperties.getTimeoutMs(), TimeUnit.MILLISECONDS);
    }

    @Override
    public void updateRequest(String requestId, InalogyRegistrationRequest request) {
        regRequestMap.remove(requestId);
        putRequest(request);
    }

    @Override
    public boolean containsKey(String requestId) {
        return regRequestMap.containsKey(requestId);
    }
    
    @Override
    public void removeRequest(String requestId) {
        regRequestMap.remove(requestId);
        secretMap.remove(requestId);
    }

    @Override
    public void reject(InalogyRegistrationRequest request) {

    }

    @Override
    public InalogyRegistrationRequest getRequestBySecret(String encodedSecret) {
        var requestId = secretMap.get(encodedSecret);
        if (requestId == null) {
            return null;
        }
        return regRequestMap.get(requestId);
    }
}
