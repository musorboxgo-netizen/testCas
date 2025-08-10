package cz.ami.cas.inauth.hazelcast.registration;

import cz.ami.cas.inauth.hazelcast.InalogyRequestMap;

public interface RegistrationRequestMap extends InalogyRequestMap<InalogyRegistrationRequest> {

    public final static String BEAN_NAME = "inalogyRegRequestMap";

    InalogyRegistrationRequest getRequestBySecret(String pushId);
}
