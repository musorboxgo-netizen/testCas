package cz.ami.cas.inauth.service;

import cz.ami.cas.inauth.authenticator.model.push.PushRegistrationStatus;
import cz.ami.cas.inauth.authenticator.model.push.ValidationResult;
import cz.ami.cas.inauth.authenticator.model.key.InalogyAuthenticatorKey;
import cz.ami.cas.inauth.authenticator.model.push.PushAuthenticationStatus;
import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorAccount;
import cz.ami.cas.inauth.credential.repository.BaseInalogyAuthenticatorTokenCredentialRepository;
import cz.ami.cas.inauth.credential.repository.InalogyOneTimeTokenCredentialRepository;
import cz.ami.cas.inauth.hazelcast.mfa.InalogyMfaRequest;
import cz.ami.cas.inauth.hazelcast.mfa.MfaRequestMap;
import cz.ami.cas.inauth.hazelcast.registration.RegistrationRequestMap;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.springframework.http.HttpStatus;

import java.util.*;

import static cz.ami.cas.inauth.authenticator.model.push.PushAuthenticationStatus.*;

/**
 * Implementation of the {@link IInalogyAuthenticator} interface.
 * This service provides the core functionality for multi-factor authentication
 * using the Inalogy Authenticator, including OTP validation, push authentication,
 * and device registration. It works directly with InalogyAuthenticatorToken,
 * InalogyAuthenticatorAccount, and other related classes.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Slf4j
@Getter
@Setter
public class InalogyAuthenticatorService implements IInalogyAuthenticator {
    /**
     * Configuration properties for the authenticator.
     */
    private final CoreInalogyMultifactorProperties properties;

    /**
     * Repository for storing and retrieving token credentials.
     */
    private final InalogyOneTimeTokenCredentialRepository tokenCredentialRepository;

    /**
     * Repository for managing push authentication requests.
     */
    private final MfaRequestMap mfaRequestMap;

    /**
     * Storage for temporary accounts during registration.
     */
    private final RegistrationRequestMap registrationRequestMap;

    /**
     * Service for sending push notifications to devices.
     */
    private final InalogyMessagingService messagingService;


    /**
     * Service for OTP operations.
     */
    private InalogyOtpService otpService;

    /**
     * Constructor for the InalogyAuthenticatorService.
     *
     * @param properties The configuration properties for the authenticator
     * @param tokenCredentialRepository Repository for storing and retrieving token credentials
     * @param mfaRequestMap Repository for managing push authentication requests
     * @param messagingService Service for sending push notifications
     * @param registrationRequestMap Storage for temporary accounts during registration
     */
    public InalogyAuthenticatorService(final CoreInalogyMultifactorProperties properties,
                                       final InalogyOneTimeTokenCredentialRepository tokenCredentialRepository,
                                       final InalogyMessagingService messagingService,
                                       final MfaRequestMap mfaRequestMap,
                                       final RegistrationRequestMap registrationRequestMap
    ) {
        this.properties = properties;
        this.tokenCredentialRepository = tokenCredentialRepository;
        this.mfaRequestMap = mfaRequestMap;
        this.messagingService = messagingService;
        this.registrationRequestMap = registrationRequestMap;
        this.otpService = new InalogyOtpService(this.properties);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates new authentication credentials including a secret key,
     * verification code, and scratch codes.
     */
    @Override
    public InalogyAuthenticatorKey createCredentials() {
            // Extracting the bytes making up the secret key.
            byte[] secretKey = otpService.generateSecretBytes();
            String generatedKey = otpService.calculateSecretKey(secretKey);

            // Generating the verification code at time = 0.
            String validationCode = otpService.generateTOTP(secretKey);

            // Calculate scratch codes
            List<Integer> scratchCodes = otpService.calculateScratchCodes();

            return new InalogyAuthenticatorKey(generatedKey, Integer.parseInt(validationCode), scratchCodes);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Validates a one-time password (OTP) for a given account.
     */
    @Override
    public boolean validateOtp(OneTimeTokenAccount account, int token) {
        try {
            return otpService.checkCode(account.getSecretKey(), token);
        } catch (NumberFormatException e) {
            LOGGER.warn("Invalid OTP format: [{}]", token);
            return false;
        }
    }

    /**
     * {@inheritDoc}
     * <p>
     * Initiates a push authentication for a user.
     */
    @Override
    public String initiatePushAuthentication(String username) {
        try {
            // Find the user's device
            val accounts = tokenCredentialRepository.get(username);
            if (accounts == null || accounts.isEmpty()) {
                LOGGER.warn("No accounts found for user: [{}]", username);
                return null;
            }

            // Find a device with push support
            Optional<InalogyAuthenticatorAccount> pushAccountOpt = accounts.stream()
                    .filter(acc -> acc instanceof InalogyAuthenticatorAccount)
                    .map(acc -> (InalogyAuthenticatorAccount) acc)
                    .filter(acc -> acc.getDeviceKeyId() != null && !acc.getDeviceKeyId().isEmpty())
                    .findFirst();

            if (pushAccountOpt.isEmpty()) {
                LOGGER.warn("No push-enabled device found for user: [{}]", username);
                return null;
            }

            val pushAccount = pushAccountOpt.get();

            String keyId = pushAccount.getDeviceKeyId();

            // Choose the challenge type and generate data
            String challengeType = properties.getChallengeType();
            Random random = new Random();
            String dataForChallenge, correctAnswer = null;

            switch (challengeType) {
                case "CHALLENGE_WRITE":
                    dataForChallenge = String.valueOf(10000 + random.nextInt(90000));
                    break;
                case "CHALLENGE_CHOOSE":
                    int num1 = random.nextInt(100);
                    int num2 = random.nextInt(100);
                    int num3 = random.nextInt(100);
                    int[] options = {num1, num2, num3};

                    // Select one as the correct answer (randomly)
                    int correctIndex = random.nextInt(3);
                    correctAnswer = String.valueOf(options[correctIndex]);

                    // Store all options as comma-separated string
                    dataForChallenge = num1 + "," + num2 + "," + num3;
                    break;
                case "CHALLENGE_APPROVE":
                default:
                    correctAnswer = "true";
                    dataForChallenge = null;
                    break;
            }

            // Form the callback URL
            String callback = properties.getCallbackUrl();

            // Create a record of the pending authentication
            val pendingAuth = InalogyMfaRequest.builder()
                    .requestId(UUID.randomUUID().toString())
                    .userId(pushAccount.getUsername())
                    .pushId(pushAccount.getPushId())
                    .accountId(pushAccount.getId())
                    .otp(null)
                    .challengeType(challengeType)
                    .challengeData(correctAnswer != null ? correctAnswer : dataForChallenge)
                    .userResponse(null)
                    .status(PENDING)
                    .validUntil(System.currentTimeMillis() + properties.getTimeoutMs())
                    .build();

            if (!challengeType.equals("CHALLENGE_CHOOSE")) {
                dataForChallenge = null;
            }

            // Send push notification
            boolean sent = messagingService.sendPushNotification(
                    pushAccount.getPushId(),
                    pushAccount.getDeviceType(),
                    challengeType,
                    dataForChallenge,
                    keyId,
                    callback
            );

            if (!sent) {
                LOGGER.error("Failed to send push notification for user: [{}]", username);
                return null;
            }

            LOGGER.debug("Initiated push authentication for user: [{}], pushId: [{}]", username, pushAccount.getPushId());
            // Save the record
            mfaRequestMap.putRequest(pendingAuth);
            return pendingAuth.getPushId();
        } catch (Exception e) {
            LOGGER.error("Error initiating push authentication for user: [{}]", username, e);
            return null;
        }
    }

    /**
     * {@inheritDoc}
     * <p>
     * Checks the status of a push authentication mfa.
     */
    @Override
    public PushAuthenticationStatus checkPushAuthenticationStatus(final String pushId) {
        val auth = mfaRequestMap.getRequestByPushId(pushId);
        if (auth == null) {
            LOGGER.debug("No pending authentication found for pushId=[{}]", pushId);
            return PushAuthenticationStatus.NOT_FOUND;
        }

        return switch (auth.getStatus()) {
            case APPROVED -> {
                LOGGER.debug("Authentication approved for pushId=[{}]", pushId);
                yield PushAuthenticationStatus.APPROVED;
            }
            case REJECTED -> {
                LOGGER.debug("Authentication rejected for pushId=[{}]", pushId);
                yield REJECTED;
            }
            case PENDING -> {
                LOGGER.debug("Authentication still pending for pushId=[{}]", pushId);
                yield PENDING;
            }
            default -> {
                LOGGER.warn("Unknown MFA status [{}] for pushId=[{}]", auth.getStatus(), pushId);
                yield REJECTED; // fallback
            }
        };
    }

    /**
     * {@inheritDoc}
     * <p>
     * Checks the status of a push registration request.
     */
    @Override
    public PushRegistrationStatus checkPushRegistrationStatus(final String requestId) {
        val auth = registrationRequestMap.getRequest(requestId);
        if (auth == null) {
            LOGGER.debug("No pending registration found for pushId=[{}]", requestId);
            return PushRegistrationStatus.NOT_FOUND;
        }

        return switch (auth.getStatus()) {
            case REGISTERED -> {
                LOGGER.debug("Registration was successfully submitted for requestId=[{}]", requestId);
                yield PushRegistrationStatus.REGISTERED;
            }
            case REJECTED -> {
                LOGGER.debug("Registration rejected for requestId=[{}]", requestId);
                yield PushRegistrationStatus.REJECTED;
            }
            case PENDING -> {
                LOGGER.debug("Registration still pending for requestId=[{}]", requestId);
                yield PushRegistrationStatus.PENDING;
            }
            default -> {
                LOGGER.warn("Unknown registration status [{}] for requestId=[{}]", auth.getStatus(), requestId);
                yield PushRegistrationStatus.REJECTED; // fallback
            }
        };
    }

    /**
     * {@inheritDoc}
     * <p>
     * Validates a challenge response based on the challenge type.
     */
    @Override
    public boolean validateChallengeResponse(String challengeType, String dataForChallenge, String challengeResponse) {
        return switch (challengeType) {
            case "CHALLENGE_APPROVE" -> "true".equals(challengeResponse);
            case "CHALLENGE_WRITE" -> dataForChallenge.equals(challengeResponse);
            case "CHALLENGE_CHOOSE" ->
                // Check if the user's response matches the correct answer
                    dataForChallenge.equals(challengeResponse);
            default -> {
                LOGGER.warn("Unknown challenge type: [{}]", challengeType);
                yield false;
            }
        };
    }

    /**
     * {@inheritDoc}
     * <p>
     * Validates a push authentication response.
     */
    @Override
    public ValidationResult validatePushAuthentication(String pushId, String otp, String challengeResponse) {
        // Find account by pushId
        val account = tokenCredentialRepository.getByPushId(pushId);
        if (account == null) {
            return ValidationResult.error(HttpStatus.FORBIDDEN, "device not found");
        }

        // Find the latest active authentication mfa
        val pendingRequest = mfaRequestMap.getRequestByPushId(pushId);
        if (pendingRequest == null) {
            return ValidationResult.error(HttpStatus.FORBIDDEN, "authentication mfa not found");
        }

        // Check OTP
        final int code;
        try {
            code = Integer.parseInt(otp);
        } catch (NumberFormatException e) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "invalid OTP format");
        }
        if (!validateOtp(account, code)) {
            mfaRequestMap.reject(pendingRequest);
            return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid OTP");
        }

        // Check the challenge response
        boolean isValidChallengeResponse = validateChallengeResponse(
                pendingRequest.getChallengeType(),
                pendingRequest.getChallengeData(),
                challengeResponse
        );

        if (!isValidChallengeResponse) {
            mfaRequestMap.reject(pendingRequest);
            return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid challenge response");
        }

        pendingRequest.setStatus(APPROVED);
        LOGGER.info("Status for request [{}] is set to 'APPROVED'", pendingRequest.getRequestId());
        pendingRequest.setOtp(otp);
        pendingRequest.setUserResponse(challengeResponse);
        // Update the authentication status
        mfaRequestMap.updateRequest(pendingRequest.getRequestId(), pendingRequest);

        return ValidationResult.success();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Retrieves a pending push authentication mfa by its key ID.
     */
    @Override
    public InalogyMfaRequest getPendingPushAuthentication(String pushId) {
        return mfaRequestMap.getRequestByPushId(pushId);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Validates a one-time password (OTP) for a given Inalogy authenticator account
     * and checks if the associated push authentication request has been approved.
     *
     * @param account The Inalogy authenticator account containing the secret key
     * @param token The OTP token to validate
     * @return true if the token is valid and the authentication request is approved, false otherwise
     */
    public boolean validateCredential(InalogyAuthenticatorAccount account, int token) {
        return validateOtp(account, token) && mfaRequestMap.getRequestByPushId(account.getPushId()).getStatus() == APPROVED;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Terminates all active push authentication requests for a device.
     */
    @Override
    public ValidationResult terminatePushAuthentication(String pushId, String otp) {
        // Find account by pushId
        val account = tokenCredentialRepository.getByPushId(pushId);
        if (account == null) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "device not found");
        }

        // Find active authentication
        val pendingRequest = mfaRequestMap.getRequestByPushId(pushId);
        if (pendingRequest == null) {
            return ValidationResult.error(HttpStatus.FORBIDDEN, "authentication mfa not found");
        }

        // Check OTP
        final int code;
        try {
            code = Integer.parseInt(otp);
        } catch (NumberFormatException e) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "invalid OTP format");
        }
        if (!validateOtp(account, code)) {
            return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid OTP");
        }

        mfaRequestMap.reject(pendingRequest);

        return ValidationResult.success();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Updates the push notification ID for a device.
     */
    @Override
    public ValidationResult updatePushId(String deviceKey, String newPushId, String otp) {
        try {
            // Find device by deviceKey
            val account = (InalogyAuthenticatorAccount) tokenCredentialRepository.getByDeviceKeyId(deviceKey);

            if (account == null) {
                return ValidationResult.error(HttpStatus.BAD_REQUEST, "device not found");
            }

            // Check OTP
            if (!validateOtp(account, Integer.parseInt(otp))) {
                return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid OTP");
            }

            val currentPushId = account.getPushId();

            val mfaRequest = mfaRequestMap.getRequestByPushId(currentPushId);
            if (mfaRequest != null) {
                mfaRequest.setPushId(newPushId);
                mfaRequestMap.updateRequest(mfaRequest.getRequestId(), mfaRequest);
            }

            // Update pushId
            InalogyAuthenticatorAccount inalogyAccount = InalogyAuthenticatorAccount.from(account);
            inalogyAccount.setPushId(newPushId);

            tokenCredentialRepository.update(inalogyAccount);
            LOGGER.debug("Updated push ID for user: [{}], device key: [{}]", account.getUsername(), deviceKey);

            return ValidationResult.success();
        } catch (Exception e) {
            LOGGER.error("Error updating push ID", e);
            return ValidationResult.error(HttpStatus.INTERNAL_SERVER_ERROR, "internal server error");
        }
    }

    /**
     * {@inheritDoc}
     * <p>
     * Registers a device for push authentication.
     */
    @Override
    public ValidationResult registerPushDevice(String encodedSecret, String deviceName,
                                               String pushId, String deviceKeyId,
                                               String deviceType, String initialCode) {
        try {

            val account = registrationRequestMap.getRequestBySecret(encodedSecret);

            if (account == null) {
                return ValidationResult.error(HttpStatus.FORBIDDEN, "didnt found account with this secret key");
            }

            val otp = Integer.parseInt(initialCode);

            account.setPushId(pushId);
            account.setDeviceKeyId(deviceKeyId);
            account.setDeviceType(deviceType);
            account.setValidationCode(otp);
            account.setDeviceName(deviceName);

            InalogyAuthenticatorAccount inalogyAccount = InalogyAuthenticatorAccount.from(account);

            // Check initialCode
            if (!validateOtp(inalogyAccount, otp)) {
                registrationRequestMap.reject(account);
                return ValidationResult.error(HttpStatus.FORBIDDEN, "otp registration data is invalid");
            }

            account.setStatus(PushRegistrationStatus.REGISTERED);
            registrationRequestMap.updateRequest(account.getRequestId(), account);

            LOGGER.debug("Registered push device for user: [{}], device: [{}]", account.getUsername(), deviceName);

            return ValidationResult.success();
        } catch (Exception e) {
            LOGGER.error("Error registering push device", e);
            return ValidationResult.error(HttpStatus.INTERNAL_SERVER_ERROR, "internal server error");
        }
    }
}
