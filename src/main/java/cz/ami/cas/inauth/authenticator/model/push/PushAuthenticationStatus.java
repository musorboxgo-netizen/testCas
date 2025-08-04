package cz.ami.cas.inauth.authenticator.model.push;

/**
 * Enum representing the possible statuses of a push authentication request.
 * 
 * @author Inalogy
 * @since 1.0.0
 */
public enum PushAuthenticationStatus {
    /**
     * The authentication request is pending and waiting for user response.
     */
    PENDING,

    /**
     * The authentication request has been approved by the user.
     */
    APPROVED,

    /**
     * The authentication request has been rejected by the user.
     */
    REJECTED,

    /**
     * The authentication request has expired due to timeout.
     */
    EXPIRED,

    /**
     * The authentication request could not be found in the system.
     */
    NOT_FOUND
}
