package cz.ami.cas.inauth.authenticator.model.push;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Represents a pending push authentication mfa.
 * This class contains all the information needed to track and validate
 * a push-based authentication challenge sent to a user's device.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Data
public class PendingPushAuthentication {

    /**
     * Creates a new pending push authentication mfa with the specified parameters.
     *
     * @param pushId The unique identifier for the authentication key
     * @param username The username of the user being authenticated
     * @param challengeType The type of challenge being used
     * @param dataForChallenge The data needed for the challenge
     * @param correctChallengeResponse The expected correct response
     * @param validitySeconds How long the mfa is valid in seconds
     */
    public PendingPushAuthentication(String pushId, String username,
                                     String challengeType, String dataForChallenge,
                                     String correctChallengeResponse, long validitySeconds) {
        this.pushId = pushId;
        this.username = username;
        this.challengeType = challengeType;
        this.dataForChallenge = dataForChallenge;
        this.correctChallengeResponse = correctChallengeResponse;
        this.createdAt = System.currentTimeMillis();
        this.validUntil = this.createdAt + (validitySeconds * 1000);
    }

    /**
     * Unique identifier for the authentication key.
     */
    private final String pushId;

    /**
     * Username of the user being authenticated.
     */
    private final String username;

    /**
     * Type of challenge being used for authentication.
     */
    private final String challengeType;

    /**
     * Data needed for the challenge, sent to the user's device.
     */
    private final String dataForChallenge;

    /**
     * The expected correct response to the challenge.
     */
    private String correctChallengeResponse;

    /**
     * Timestamp when the authentication mfa was created.
     */
    private final long createdAt;

    /**
     * Timestamp until when the authentication mfa is valid.
     */
    private final long validUntil;

    /**
     * Flag indicating if the mfa has been responded to.
     */
    private boolean responded = false;

    /**
     * Flag indicating if the mfa has been approved.
     */
    private boolean approved = false;

    /**
     * Timestamp when the mfa was responded to.
     */
    private long respondedAt = 0;

    /**
     * Checks if the authentication mfa has expired.
     *
     * @return true if the current time is after the validUntil timestamp, false otherwise
     */
    public boolean isExpired() {
        return System.currentTimeMillis() > validUntil;
    }

    /**
     * Sets the response for this authentication mfa.
     *
     * @param approved true if the mfa is approved, false if rejected
     */
    public void setResponse(boolean approved) {
        this.responded = true;
        this.approved = approved;
        this.respondedAt = System.currentTimeMillis();
    }
}
