package cz.ami.cas.inauth.hazelcast.registration;

import cz.ami.cas.inauth.authenticator.model.push.PushRegistrationStatus;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorAccount;
import lombok.Builder;
import lombok.Data;
import org.apereo.cas.authentication.OneTimeTokenAccount;

import java.io.Serializable;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Data class representing a registration request for the authentication system.
 * This class stores all information related to a device registration request,
 * including user information, device details, authentication secrets, and status.
 * It is designed to be stored in a distributed Hazelcast map.
 */
@Data
@Builder
public class InalogyRegistrationRequest implements Serializable {
    /**
     * Unique identifier for the account in the system.
     */
    private long   id;

    /**
     * Unique identifier for the registration request.
     */
    private String requestId;

    /**
     * Username of the user initiating the registration.
     */
    private String username;

    /**
     * Name of the device being registered.
     */
    private String deviceName;

    /**
     * Type of the device being registered (e.g., "mobile", "tablet").
     */
    private String deviceType;

    /**
     * Identifier for push notifications to this device.
     */
    private String pushId;

    /**
     * Identifier for the device's cryptographic key.
     */
    private String deviceKeyId;

    /**
     * Encoded secret key used for authentication.
     */
    private String encodedSecret;

    /**
     * Validation code for verifying the registration.
     */
    private int    validationCode;

    /**
     * List of scratch codes that can be used for recovery.
     */
    private List<Number> scratchCodes;

    /**
     * Source of the registration request (e.g., "web", "mobile app").
     */
    private String source;

    /**
     * Date and time when the registration was initiated.
     */
    private ZonedDateTime registrationDate;

    /**
     * Timestamp indicating when this registration request expires.
     */
    private long validUntil;

    /**
     * Current status of the registration request (e.g., PENDING, APPROVED, REJECTED).
     */
    private PushRegistrationStatus status;

    /**
     * Factory method to create a registration request from a OneTimeTokenAccount.
     * Initializes a new registration request with information from the account
     * and sets default values for device-specific fields.
     *
     * @param acct The OneTimeTokenAccount containing basic account information
     * @param timeoutMs The timeout in milliseconds for this registration request
     * @return A new InalogyRegistrationRequest initialized with the account information
     */
    public static InalogyRegistrationRequest of(OneTimeTokenAccount acct,
                                                long timeoutMs) {
        return InalogyRegistrationRequest.builder()
                .id(acct.getId())
                .requestId(UUID.randomUUID().toString())
                .username(acct.getUsername())
                .deviceName(null)
                .deviceType(null)
                .pushId(null)
                .registrationDate(ZonedDateTime.now(ZoneOffset.UTC))
                .deviceKeyId(null)
                .encodedSecret(acct.getSecretKey())
                .validationCode(acct.getValidationCode())
                .scratchCodes(new ArrayList<>(acct.getScratchCodes()))
                .validUntil(System.currentTimeMillis() + timeoutMs)
                .status(PushRegistrationStatus.PENDING)
                .build();
    }
}
