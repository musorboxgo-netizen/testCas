package cz.ami.cas.inauth.service;

import cz.ami.cas.inauth.authenticator.model.push.ValidationResult;
import cz.ami.cas.inauth.authenticator.model.key.InalogyAuthenticatorKey;
import cz.ami.cas.inauth.authenticator.model.push.PushAuthenticationStatus;
import org.apereo.cas.authentication.OneTimeTokenAccount;

/**
 * Inalogy Authenticator library interface.
 *
 * @author Inalogy
 * @since 1.0.0
 */
public interface IInalogyAuthenticator {

    boolean validateOtp(OneTimeTokenAccount account, int token);

    InalogyAuthenticatorKey createCredentials();

    ValidationResult updatePushId(String deviceKey, String newPushId, String otp);

    ValidationResult validatePushAuthentication(String pushId, String otp, String challengeResponse);

    ValidationResult terminatePushAuthentication(String pushId, String otp);

    ValidationResult registerPushDevice(String encodedSecret, String deviceName,
                                               String pushId, String deviceKeyId,
                                               String deviceType, String initialCode);

    String initiatePushAuthentication(String username, String callbackBaseUrl);

    PushAuthenticationStatus checkPushAuthenticationStatus(String keyId);

    boolean validateChallengeResponse(String challengeType, String dataForChallenge, String challengeResponse);
}