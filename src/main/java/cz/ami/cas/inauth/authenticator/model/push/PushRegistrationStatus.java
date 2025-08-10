package cz.ami.cas.inauth.authenticator.model.push;

/**
 * Enum representing the possible statuses of a push authentication mfa.
 * 
 * @author Inalogy
 * @since 1.0.0
 */
public enum PushRegistrationStatus {
    /**
     * The authentication mfa is pending and waiting for user response.
     */
    PENDING,

    /**
     * The authentication mfa has been approved by the user.
     */
    REGISTERED,

    REJECTED,

    /**
     * The authentication mfa has expired due to timeout.
     */
    EXPIRED
}
