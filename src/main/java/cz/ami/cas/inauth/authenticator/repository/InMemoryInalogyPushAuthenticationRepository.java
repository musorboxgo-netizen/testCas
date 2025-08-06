package cz.ami.cas.inauth.authenticator.repository;

import cz.ami.cas.inauth.authenticator.model.push.PendingPushAuthentication;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.util.concurrent.CasReentrantLock;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * In-memory implementation of the {@link IInalogyPushAuthenticationRepository} interface.
 * This class stores push authentication requests in memory using a ConcurrentHashMap
 * and provides thread-safe access using a CasReentrantLock.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Slf4j
public class InMemoryInalogyPushAuthenticationRepository implements IInalogyPushAuthenticationRepository {

    /**
     * Lock for thread-safe access to the repository.
     */
    private final CasReentrantLock lock = new CasReentrantLock();

    /**
     * Map of pending authentication requests indexed by their key ID.
     */
    private final Map<String, PendingPushAuthentication> pendingAuthentications = new ConcurrentHashMap<>();

    /**
     * {@inheritDoc}
     * <p>
     * This implementation stores the authentication request in the in-memory map
     * and logs the operation.
     */
    @Override
    public void save(PendingPushAuthentication authentication) {
        lock.tryLock(__ -> {
            pendingAuthentications.put(authentication.getPushId(), authentication);
            LOGGER.debug("Saved pending authentication with pushId: [{}]", authentication.getPushId());
        });
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation retrieves the authentication request from the in-memory map.
     */
    @Override
    public Optional<PendingPushAuthentication> findByPushId(String pushId) {
        return lock.tryLock(() -> Optional.ofNullable(pendingAuthentications.get(pushId)));
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation filters the in-memory map to find all authentication
     * requests for the specified username.
     */
    @Override
    public List<PendingPushAuthentication> findByUsername(String username) {
        return lock.tryLock(() -> pendingAuthentications.values().stream()
                .filter(auth -> username.equals(auth.getUsername()))
                .collect(Collectors.toList()));
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation updates the response status of the authentication request
     * in the in-memory map and logs the operation.
     */
    @Override
    public void updateResponse(String pushId, boolean approved) {
        lock.tryLock(() -> {
            Optional<PendingPushAuthentication> authOpt = Optional.ofNullable(pendingAuthentications.get(pushId));
            if (authOpt.isPresent()) {
                authOpt.get().setResponse(approved);
                authOpt.get().setRespondedAt(System.currentTimeMillis());
                authOpt.get().setResponded(true);
                LOGGER.debug("Updated pending authentication response for pushId: [{}], approved: [{}]",
                        pushId, approved);
                return true;
            }
            return false;
        });
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation removes the authentication request from the in-memory map
     * and logs the operation.
     */
    @Override
    public boolean remove(String pushId) {
        return lock.tryLock(() -> {
            PendingPushAuthentication removed = pendingAuthentications.remove(pushId);
            if (removed != null) {
                LOGGER.debug("Removed pending authentication with pushId: [{}]", pushId);
                return true;
            }
            return false;
        });
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation runs every minute to clean up expired authentication requests
     * and those that have been responded to more than 3 minutes ago.
     */
    @Override
    @Scheduled(fixedRate = 60000) // Run every minute
    public int cleanupExpired() {
        return lock.tryLock(() -> {
            List<String> expiredKeys = pendingAuthentications.entrySet().stream()
                    .filter(entry -> entry.getValue().isExpired() ||
                            (entry.getValue().isResponded() &&
                                    System.currentTimeMillis() - entry.getValue().getRespondedAt() > 180000))
                    .map(Map.Entry::getKey)
                    .toList();

            int count = expiredKeys.size();
            expiredKeys.forEach(pendingAuthentications::remove);

            if (count > 0) {
                LOGGER.debug("Cleaned up [{}] expired pending authentications", count);
            }

            return count;
        });
    }
}
