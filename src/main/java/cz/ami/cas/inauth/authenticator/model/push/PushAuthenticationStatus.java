package cz.ami.cas.inauth.authenticator.model.push;

/**
 * Enum representing the possible statuses of a push authentication mfa.
 * 
 * @author Inalogy
 * @since 1.0.0
 */
public enum PushAuthenticationStatus {
    /**
     * The authentication mfa is pending and waiting for user response.
     */
    PENDING,

    /**
     * The authentication mfa has been approved by the user.
     */
    APPROVED,

    /**
     * The authentication mfa has been rejected by the user.
     */
    REJECTED,

    /**
     * The authentication mfa could not be found in the system.
     */
    NOT_FOUND
}
