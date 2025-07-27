package cz.ami.cas.inauth.authenticator.repository;

import cz.ami.cas.inauth.authenticator.model.push.PendingPushAuthentication;

import java.util.List;
import java.util.Optional;

public interface IInalogyPushAuthenticationRepository {

    String BEAN_NAME = "inalogyPushAuthenticationRepository";

    void save(PendingPushAuthentication authentication);

    Optional<PendingPushAuthentication> findByKeyId(String keyId);

    List<PendingPushAuthentication> findByUsername(String username);

    boolean updateResponse(String keyId, boolean approved);

    boolean remove(String keyId);

    int cleanupExpired();
}
