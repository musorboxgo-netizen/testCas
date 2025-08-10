package cz.ami.cas.inauth.hazelcast;

public interface InalogyRequestMap<T> {

    final static String BEAN_NAME = "inalogyRequestMap";

    T getRequest(String requestId);

    void putRequest(T request);

    void updateRequest(String requestId, T request);

    void removeRequest(String requestId);

    boolean containsKey(String requestId);

    void reject(T request);
}
