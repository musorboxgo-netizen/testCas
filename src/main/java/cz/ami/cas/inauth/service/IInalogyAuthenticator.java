package cz.ami.cas.inauth.service;

import cz.ami.cas.inauth.authenticator.model.push.PendingPushAuthentication;
import cz.ami.cas.inauth.authenticator.model.push.ValidationResult;
import cz.ami.cas.inauth.authenticator.model.key.InalogyAuthenticatorKey;
import cz.ami.cas.inauth.authenticator.model.push.PushAuthenticationStatus;
import org.apereo.cas.authentication.OneTimeTokenAccount;

/**
 * Inalogy Authenticator library interface.
 * This interface defines all operations needed for multi-factor authentication
 * using the Inalogy Authenticator, including OTP validation, push authentication,
 * and device registration.
 *
 * @author Inalogy
 * @since 1.0.0
 */
public interface IInalogyAuthenticator {

    /**
     * Validates a one-time password (OTP) for a given account.
     *
     * @param account The account containing the secret key
     * @param token The OTP token to validate
     * @return true if the token is valid, false otherwise
     */
    boolean validateOtp(OneTimeTokenAccount account, int token);

    /**
     * Creates new authentication credentials.
     *
     * @return A new InalogyAuthenticatorKey containing the secret key, verification code, and scratch codes
     */
    InalogyAuthenticatorKey createCredentials();

    /**
     * Updates the push notification ID for a device.
     *
     * @param deviceKey The device key identifier
     * @param newPushId The new push notification ID
     * @param otp A valid OTP to authorize the update
     * @return A ValidationResult indicating success or failure with error details
     */
    ValidationResult updatePushId(String deviceKey, String newPushId, String otp);

    /**
     * Validates a push authentication response.
     *
     * @param pushId The push notification ID of the device
     * @param otp A valid OTP to authorize the validation
     * @param challengeResponse The user's response to the authentication challenge
     * @return A ValidationResult indicating success or failure with error details
     */
    ValidationResult validatePushAuthentication(String pushId, String otp, String challengeResponse);

    /**
     * Terminates all active push authentication requests for a device.
     *
     * @param pushId The push notification ID of the device
     * @param otp A valid OTP to authorize the termination
     * @return A ValidationResult indicating success or failure with error details
     */
    ValidationResult terminatePushAuthentication(String pushId, String otp);

    /**
     * Registers a device for push authentication.
     *
     * @param encodedSecret The encoded secret key
     * @param deviceName The name of the device
     * @param pushId The push notification ID for the device
     * @param deviceKeyId The device key identifier
     * @param deviceType The type of device (e.g., "IOS", "ANDROID")
     * @param initialCode An initial OTP to verify the registration
     * @return A ValidationResult indicating success or failure with error details
     */
    ValidationResult registerPushDevice(String encodedSecret, String deviceName,
                                               String pushId, String deviceKeyId,
                                               String deviceType, String initialCode);

    /**
     * Initiates a push authentication request for a user.
     *
     * @param username The username of the user to authenticate
     * @return The key ID of the created authentication request, or null if the request failed
     */
    String initiatePushAuthentication(String username);

    /**
     * Checks the status of a push authentication request.
     *
     * @param keyId The key ID of the authentication request
     * @return The current status of the authentication request
     */
    PushAuthenticationStatus checkPushAuthenticationStatus(String keyId);

    /**
     * Retrieves a pending push authentication request.
     *
     * @param keyId The key ID of the authentication request
     * @return The pending push authentication request, or null if not found
     */
    PendingPushAuthentication getPendingPushAuthentication(String keyId);

    /**
     * Validates a challenge response based on the challenge type.
     *
     * @param challengeType The type of challenge (e.g., "CHALLENGE_APPROVE", "CHALLENGE_WRITE", "CHALLENGE_CHOOSE")
     * @param dataForChallenge The data provided for the challenge
     * @param challengeResponse The user's response to the challenge
     * @return true if the response is valid, false otherwise
     */
    boolean validateChallengeResponse(String challengeType, String dataForChallenge, String challengeResponse);
}
