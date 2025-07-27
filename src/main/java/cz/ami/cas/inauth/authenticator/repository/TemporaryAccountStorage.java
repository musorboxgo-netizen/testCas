package cz.ami.cas.inauth.authenticator.repository;

import cz.ami.cas.inauth.credential.InalogyAuthenticatorAccount;
import lombok.val;
import org.apereo.cas.authentication.OneTimeTokenAccount;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class TemporaryAccountStorage {
    private static final Map<Long, OneTimeTokenAccount> ACCOUNTS_BY_ID = new ConcurrentHashMap<>();

    private static final Map<String, Long> SECRET_TO_ACCOUNT_ID_MAP = new ConcurrentHashMap<>();

    private static final Map<Long, String> REGISTRATION_STATUS = new ConcurrentHashMap<>();

    // Константы для статусов
    public static final String STATUS_WAITING = "WAIT_FOR_REGISTER";
    public static final String STATUS_REGISTERED = "REGISTERED";
    public static final String STATUS_REJECTED = "REJECTED";

    public void storeAccount(OneTimeTokenAccount account) {
        ACCOUNTS_BY_ID.put(account.getId(), account);
        SECRET_TO_ACCOUNT_ID_MAP.put(account.getSecretKey(), account.getId());
        REGISTRATION_STATUS.put(account.getId(), STATUS_WAITING);
    }

    public void updateRegistrationStatus(Long accountId, String status) {
        REGISTRATION_STATUS.put(accountId, status);
    }
    
    public String getRegistrationStatus(Long accountId) {
        return REGISTRATION_STATUS.getOrDefault(accountId, STATUS_WAITING);
    }

    public Optional<OneTimeTokenAccount> findBySecret(String secret) {
        Long accountId = SECRET_TO_ACCOUNT_ID_MAP.get(secret);
        if (accountId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(ACCOUNTS_BY_ID.get(accountId));
    }

    public Optional<OneTimeTokenAccount> findById(Long accountId) {
        return Optional.ofNullable(ACCOUNTS_BY_ID.get(accountId));
    }

    public void updateAccount(Long accountId, String pushId, String deviceKeyId, String deviceType, String deviceName) {
        OneTimeTokenAccount account = ACCOUNTS_BY_ID.get(accountId);

        if (account instanceof InalogyAuthenticatorAccount inalogyAccount) {
            inalogyAccount.setPushId(pushId);
            inalogyAccount.setDeviceKeyId(deviceKeyId);
            inalogyAccount.setDeviceType(deviceType);
            inalogyAccount.setName(deviceName);

            REGISTRATION_STATUS.put(accountId, STATUS_REGISTERED);
        }
    }

    public void removeAccount(Long accountId) {
        val key = ACCOUNTS_BY_ID.get(accountId).getSecretKey();
        SECRET_TO_ACCOUNT_ID_MAP.remove(key);
        REGISTRATION_STATUS.remove(accountId);
    }
}
