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

@Slf4j
public class InMemoryInalogyPushAuthenticationRepository implements IInalogyPushAuthenticationRepository {

    private final CasReentrantLock lock = new CasReentrantLock();
    private final Map<String, PendingPushAuthentication> pendingAuthentications = new ConcurrentHashMap<>();

    @Override
    public void save(PendingPushAuthentication authentication) {
        lock.tryLock(__ -> {
            pendingAuthentications.put(authentication.getKeyId(), authentication);
            LOGGER.debug("Saved pending authentication with keyId: [{}]", authentication.getKeyId());
        });
    }

    @Override
    public Optional<PendingPushAuthentication> findByKeyId(String keyId) {
        return lock.tryLock(() -> Optional.ofNullable(pendingAuthentications.get(keyId)));
    }

    @Override
    public List<PendingPushAuthentication> findByUsername(String username) {
        return lock.tryLock(() -> pendingAuthentications.values().stream()
                .filter(auth -> username.equals(auth.getUsername()))
                .collect(Collectors.toList()));
    }

    @Override
    public boolean updateResponse(String keyId, boolean approved) {
        return lock.tryLock(() -> {
            Optional<PendingPushAuthentication> authOpt = Optional.ofNullable(pendingAuthentications.get(keyId));
            if (authOpt.isPresent()) {
                authOpt.get().setResponse(approved);
                LOGGER.debug("Updated pending authentication response for keyId: [{}], approved: [{}]",
                        keyId, approved);
                return true;
            }
            return false;
        });
    }

    @Override
    public boolean remove(String keyId) {
        return lock.tryLock(() -> {
            PendingPushAuthentication removed = pendingAuthentications.remove(keyId);
            if (removed != null) {
                LOGGER.debug("Removed pending authentication with keyId: [{}]", keyId);
                return true;
            }
            return false;
        });
    }

    @Override
    @Scheduled(fixedRate = 60000) // Запускать каждую минуту
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
