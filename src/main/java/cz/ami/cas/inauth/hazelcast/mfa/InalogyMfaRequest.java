package cz.ami.cas.inauth.hazelcast.mfa;

import cz.ami.cas.inauth.authenticator.model.push.PushAuthenticationStatus;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

/**
 * Data class representing a Multi-Factor Authentication (MFA) request.
 * This class stores all information related to an MFA request, including
 * identifiers, authentication data, challenge information, and status.
 * It is designed to be stored in a distributed Hazelcast map.
 */
@Data
@Builder
public class InalogyMfaRequest implements Serializable {
    /**
     * Unique identifier for the MFA request.
     */
    private String requestId;

    /**
     * Identifier of the user who initiated the MFA request.
     */
    private String userId;

    /**
     * Identifier for push notification related to this MFA request.
     */
    private String pushId;

    /**
     * Identifier of the user's account in the authentication system.
     */
    private Long accountId;

    /**
     * One-time password associated with this MFA request.
     */
    private String otp;

    /**
     * Type of authentication challenge (e.g., "push", "otp").
     */
    private String challengeType;

    /**
     * Additional data related to the authentication challenge.
     */
    private String challengeData;

    /**
     * User's response to the authentication challenge.
     */
    private String userResponse;

    /**
     * Current status of the authentication request (e.g., PENDING, APPROVED, REJECTED).
     */
    private PushAuthenticationStatus status;

    /**
     * Timestamp indicating when this request expires.
     */
    private long validUntil;
}
