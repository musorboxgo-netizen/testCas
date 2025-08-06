package cz.ami.cas.inauth.authenticator.repository;

import cz.ami.cas.inauth.credential.InalogyAuthenticatorAccount;
import lombok.val;
import org.apereo.cas.authentication.OneTimeTokenAccount;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Temporary storage for accounts during the registration process.
 * This class provides in-memory storage for accounts that are in the process
 * of being registered, along with their registration status.
 *
 * @author Inalogy
 * @since 1.0.0
 */
public class TemporaryAccountStorage {
    /**
     * Map of accounts indexed by their ID.
     */
    private /*static*/ final Map<Long, OneTimeTokenAccount> ACCOUNTS_BY_ID = new ConcurrentHashMap<>();

    /**
     * Map of account IDs indexed by their secret key.
     */
    private /*static*/ final Map<String, Long> SECRET_TO_ACCOUNT_ID_MAP = new ConcurrentHashMap<>();

    /**
     * Map of registration statuses indexed by account ID.
     */
    private /*static*/ final Map<Long, String> REGISTRATION_STATUS = new ConcurrentHashMap<>();

    // Status constants
    /**
     * Status indicating the account is waiting for registration.
     */
    public static final String STATUS_WAITING = "WAIT_FOR_REGISTER";

    /**
     * Status indicating the account has been successfully registered.
     */
    public static final String STATUS_REGISTERED = "REGISTERED";

    /**
     * Status indicating the registration has been rejected.
     */
    public static final String STATUS_REJECTED = "REJECTED";

    /**
     * Stores a new account in the temporary storage.
     * Sets the initial registration status to STATUS_WAITING.
     *
     * @param account The account to store
     */
    public void storeAccount(OneTimeTokenAccount account) {
        ACCOUNTS_BY_ID.put(account.getId(), account);
        SECRET_TO_ACCOUNT_ID_MAP.put(account.getSecretKey(), account.getId());
        REGISTRATION_STATUS.put(account.getId(), STATUS_WAITING);
    }

    /**
     * Updates the registration status for an account.
     *
     * @param accountId The ID of the account to update
     * @param status The new registration status
     */
    public void updateRegistrationStatus(Long accountId, String status) {
        REGISTRATION_STATUS.put(accountId, status);
    }

    /**
     * Gets the current registration status for an account.
     * Returns STATUS_WAITING if no status is found.
     *
     * @param accountId The ID of the account
     * @return The current registration status
     */
    public String getRegistrationStatus(Long accountId) {
        return REGISTRATION_STATUS.getOrDefault(accountId, STATUS_WAITING);
    }

    /**
     * Finds an account by its secret key.
     *
     * @param secret The secret key to search for
     * @return An Optional containing the account if found, or empty if not found
     */
    public Optional<OneTimeTokenAccount> findBySecret(String secret) {
        Long accountId = SECRET_TO_ACCOUNT_ID_MAP.get(secret);
        if (accountId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(ACCOUNTS_BY_ID.get(accountId));
    }

    /**
     * Finds an account by its ID.
     *
     * @param accountId The ID of the account to find
     * @return An Optional containing the account if found, or empty if not found
     */
    public Optional<OneTimeTokenAccount> findById(Long accountId) {
        return Optional.ofNullable(ACCOUNTS_BY_ID.get(accountId));
    }

    /**
     * Updates an account with device information after successful registration.
     * Sets the registration status to STATUS_REGISTERED.
     *
     * @param accountId The ID of the account to update
     * @param pushId The push notification ID for the device
     * @param deviceKeyId The key ID for the device
     * @param deviceType The type of device
     * @param deviceName The name of the device
     */
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

    /**
     * Removes an account from the temporary storage.
     *
     * @param accountId The ID of the account to remove
     */
    public void removeAccount(Long accountId) {
        val key = ACCOUNTS_BY_ID.get(accountId).getSecretKey();
        SECRET_TO_ACCOUNT_ID_MAP.remove(key);
        REGISTRATION_STATUS.remove(accountId);
    }
}
