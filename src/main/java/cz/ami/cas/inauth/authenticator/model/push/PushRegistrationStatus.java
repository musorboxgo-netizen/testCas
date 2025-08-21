package cz.ami.cas.inauth.authenticator.model.push;

/**
 * Enum representing the possible statuses of a push authentication mfa.
 * 
 * @author Inalogy
 * @since 1.0.0
 */
public enum PushRegistrationStatus {
    /**
     * The mfa registration is pending and waiting for user response.
     */
    PENDING,

    /**
     * The mfa registration has been successfully submitted for the user.
     */
    REGISTERED,

    /**
     * The mfa registration request was rejected due to invalid submission request or invalid otp.
     */
    REJECTED,

    NOT_FOUND
}
