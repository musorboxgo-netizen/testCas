package cz.ami.cas.inauth.hazelcast.mfa;

import cz.ami.cas.inauth.hazelcast.InalogyRequestMap;

public interface MfaRequestMap extends InalogyRequestMap<InalogyMfaRequest> {

    public final static String BEAN_NAME = "inalogyMfaRequestMap";

    InalogyMfaRequest getRequestByPushId(String pushId);

}
