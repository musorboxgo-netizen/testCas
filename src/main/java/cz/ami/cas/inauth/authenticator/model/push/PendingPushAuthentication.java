package cz.ami.cas.inauth.authenticator.model.push;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Represents a pending push authentication request.
 * This class contains all the information needed to track and validate
 * a push-based authentication challenge sent to a user's device.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Data
@AllArgsConstructor
public class PendingPushAuthentication {
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
     * Timestamp when the authentication request was created.
     */
    private final long createdAt;

    /**
     * Timestamp until when the authentication request is valid.
     */
    private final long validUntil;

    /**
     * Flag indicating if the request has been responded to.
     */
    private boolean responded = false;

    /**
     * Flag indicating if the request has been approved.
     */
    private boolean approved = false;

    /**
     * Timestamp when the request was responded to.
     */
    private long respondedAt = 0;

    /**
     * Creates a new pending push authentication request with the specified parameters.
     *
     * @param pushId The unique identifier for the authentication key
     * @param username The username of the user being authenticated
     * @param challengeType The type of challenge being used
     * @param dataForChallenge The data needed for the challenge
     * @param correctChallengeResponse The expected correct response
     * @param validitySeconds How long the request is valid in seconds
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
     * Checks if the authentication request has expired.
     *
     * @return true if the current time is after the validUntil timestamp, false otherwise
     */
    public boolean isExpired() {
        return System.currentTimeMillis() > validUntil;
    }

    /**
     * Sets the response for this authentication request.
     *
     * @param approved true if the request is approved, false if rejected
     */
    public void setResponse(boolean approved) {
        this.responded = true;
        this.approved = approved;
        this.respondedAt = System.currentTimeMillis();
    }
}
