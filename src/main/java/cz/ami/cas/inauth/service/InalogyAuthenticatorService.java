package cz.ami.cas.inauth.service;

import cz.ami.cas.inauth.authenticator.model.push.ValidationResult;
import cz.ami.cas.inauth.authenticator.model.key.InalogyAuthenticatorKey;
import cz.ami.cas.inauth.authenticator.model.push.PendingPushAuthentication;
import cz.ami.cas.inauth.authenticator.model.push.PushAuthenticationStatus;
import cz.ami.cas.inauth.authenticator.repository.IInalogyPushAuthenticationRepository;
import cz.ami.cas.inauth.authenticator.repository.TemporaryAccountStorage;
import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorAccount;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.springframework.http.HttpStatus;

import java.util.*;
import java.util.stream.Collectors;

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
    private final OneTimeTokenCredentialRepository tokenCredentialRepository;

    /**
     * Repository for managing push authentication requests.
     */
    private final IInalogyPushAuthenticationRepository pushAuthenticationRepository;

    /**
     * Service for sending push notifications to devices.
     */
    private final InalogyMessagingService messagingService;

    /**
     * Storage for temporary accounts during registration.
     */
    private final TemporaryAccountStorage temporaryAccountStorage;

    /**
     * Service for OTP operations.
     */
    private InalogyOtpService otpService;

    /**
     * Constructor for the InalogyAuthenticatorService.
     *
     * @param properties The configuration properties for the authenticator
     * @param tokenCredentialRepository Repository for storing and retrieving token credentials
     * @param pushAuthenticationRepository Repository for managing push authentication requests
     * @param messagingService Service for sending push notifications
     * @param temporaryAccountStorage Storage for temporary accounts during registration
     */
    public InalogyAuthenticatorService(final CoreInalogyMultifactorProperties properties,
                                       final OneTimeTokenCredentialRepository tokenCredentialRepository,
                                       final IInalogyPushAuthenticationRepository pushAuthenticationRepository,
                                       final InalogyMessagingService messagingService,
                                       final TemporaryAccountStorage temporaryAccountStorage
    ) {
        this.properties = properties;
        this.tokenCredentialRepository = tokenCredentialRepository;
        this.pushAuthenticationRepository = pushAuthenticationRepository;
        this.messagingService = messagingService;
        this.temporaryAccountStorage = temporaryAccountStorage;
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
        if (properties.isTestMode()) {
            String generatedKey = "JBSWY3DPEHPK3PXP";

            int validationCode = 123456;

            List<Integer> scratchCodes = Arrays.asList(1234, 5678, 9012, 3456, 7890);

            return new InalogyAuthenticatorKey(generatedKey, validationCode, scratchCodes);

        } else {
            // Extracting the bytes making up the secret key.
            byte[] secretKey = otpService.generateSecretBytes();
            String generatedKey = otpService.calculateSecretKey(secretKey);

            // Generating the verification code at time = 0.
            String validationCode = otpService.generateTOTP(secretKey);

            // Calculate scratch codes
            List<Integer> scratchCodes = otpService.calculateScratchCodes();

            return new InalogyAuthenticatorKey(generatedKey, Integer.parseInt(validationCode), scratchCodes);
        }
    }

    /**
     * Finds an account by its push notification ID.
     *
     * @param pushId The push notification ID to search for
     * @return An Optional containing the account if found, or empty if not found
     */
    public Optional<InalogyAuthenticatorAccount> findAccountByPushId(String pushId) {
        return tokenCredentialRepository.load().stream()
                .filter(acc -> acc instanceof InalogyAuthenticatorAccount)
                .map(acc -> (InalogyAuthenticatorAccount) acc)
                .filter(acc -> pushId.equals(acc.getPushId()))
                .findFirst();
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
     * Finds active authentication requests for a user.
     *
     * @param username The username of the user
     * @return A list of active authentication requests
     */
    public List<PendingPushAuthentication> findActivePendingAuthentications(String username) {
        return pushAuthenticationRepository.findByUsername(username).stream()
                .filter(auth -> !auth.isResponded() && !auth.isExpired())
                .collect(Collectors.toList());
    }

    /**
     * Finds the latest active authentication request for a user.
     *
     * @param username The username of the user
     * @return An Optional containing the found request, or an empty Optional if none found
     */
    public Optional<PendingPushAuthentication> findLatestPendingAuthentication(String username) {
        return findActivePendingAuthentications(username).stream()
                .max(Comparator.comparing(PendingPushAuthentication::getCreatedAt));
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

            // Generate a unique keyId
            String keyId = UUID.randomUUID().toString();

            // Choose the challenge type and generate data
            String challengeType = properties.getChallengeType();
            Random random = new Random();
            String dataForChallenge, correctAnswer = null;

            switch (challengeType) {
                case "CHALLENGE_WRITE":
                    dataForChallenge = /*"123456"*/String.valueOf(10000 + random.nextInt(90000));
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
                    dataForChallenge = null;
                    break;
            }

            // Form the callback URL
            String callback = properties.getCallbackUrl();

            // Create a record of the pending authentication
            val pendingAuth = new PendingPushAuthentication(
                    keyId, username, challengeType, dataForChallenge, correctAnswer, 300
            );

            if (!challengeType.equals("CHALLENGE_CHOOSE")) {
                dataForChallenge = null;
            }

            // Send push notification
            boolean sent = messagingService.sendPushNotification(
                    pushAccount.getDeviceKeyId(),
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

            LOGGER.debug("Initiated push authentication for user: [{}], keyId: [{}]", username, keyId);
            // Save the record
            pushAuthenticationRepository.save(pendingAuth);
            return keyId;
        } catch (Exception e) {
            LOGGER.error("Error initiating push authentication for user: [{}]", username, e);
            return null;
        }
    }

    /**
     * {@inheritDoc}
     * <p>
     * Checks the status of a push authentication request.
     */
    @Override
    public PushAuthenticationStatus checkPushAuthenticationStatus(String keyId) {
        Optional<PendingPushAuthentication> authOpt = pushAuthenticationRepository.findByKeyId(keyId);

        if (authOpt.isEmpty()) {
            LOGGER.debug("No pending authentication found for keyId: [{}]", keyId);
            return PushAuthenticationStatus.NOT_FOUND;
        }

        PendingPushAuthentication auth = authOpt.get();

        if (auth.isExpired()) {
            LOGGER.debug("Authentication request expired for keyId: [{}]", keyId);
            pushAuthenticationRepository.remove(keyId);
            return PushAuthenticationStatus.EXPIRED;
        }

        if (auth.isResponded()) {
            if (auth.isApproved()) {
                LOGGER.debug("Authentication approved for keyId: [{}]", keyId);
                return PushAuthenticationStatus.APPROVED;
            } else {
                LOGGER.debug("Authentication rejected for keyId: [{}]", keyId);
                return PushAuthenticationStatus.REJECTED;
            }
        }

        LOGGER.debug("Authentication pending for keyId: [{}]", keyId);
        return PushAuthenticationStatus.PENDING;
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
        Optional<InalogyAuthenticatorAccount> accountOpt = findAccountByPushId(pushId);
        if (accountOpt.isEmpty()) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "device not found");
        }

        // Check OTP
        InalogyAuthenticatorAccount account = accountOpt.get();
        if (!validateOtp(account, Integer.parseInt(otp))) {
            return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid OTP");
        }

        // Find the latest active authentication request
        Optional<PendingPushAuthentication> pendingAuthOpt = findLatestPendingAuthentication(account.getUsername());
        if (pendingAuthOpt.isEmpty()) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "authentication request not found");
        }

        PendingPushAuthentication pendingAuth = pendingAuthOpt.get();

        // Check the challenge response
        boolean isValidChallengeResponse = validateChallengeResponse(
                pendingAuth.getChallengeType(),
                pendingAuth.getDataForChallenge(),
                challengeResponse
        );

        if (!isValidChallengeResponse) {
            return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid challenge response");
        }

        // Update the authentication status
        pushAuthenticationRepository.updateResponse(pendingAuth.getKeyId(), true);

        return ValidationResult.success();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Retrieves a pending push authentication request by its key ID.
     */
    @Override
    public PendingPushAuthentication getPendingPushAuthentication(String keyId) {
        return pushAuthenticationRepository.findByKeyId(keyId).orElse(null);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Terminates all active push authentication requests for a device.
     */
    @Override
    public ValidationResult terminatePushAuthentication(String pushId, String otp) {
        // Find account by pushId
        Optional<InalogyAuthenticatorAccount> accountOpt = findAccountByPushId(pushId);
        if (accountOpt.isEmpty()) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "device not found");
        }

        // Check OTP
        InalogyAuthenticatorAccount account = accountOpt.get();
        if (!validateOtp(account, Integer.parseInt(otp))) {
            return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid OTP");
        }

        // Find active authentications
        List<PendingPushAuthentication> activeAuths = findActivePendingAuthentications(account.getUsername());
        if (activeAuths.isEmpty()) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "no active authentication requests found");
        }

        // Reject all active authentications
        for (PendingPushAuthentication auth : activeAuths) {
            pushAuthenticationRepository.updateResponse(auth.getKeyId(), false);
        }

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
            Optional<OneTimeTokenAccount> accountOpt = tokenCredentialRepository.load().stream()
                    .filter(acc -> acc instanceof InalogyAuthenticatorAccount)
                    .map(acc -> (InalogyAuthenticatorAccount) acc)
                    .filter(acc -> deviceKey.equals(acc.getDeviceKeyId()))
                    .map(acc -> (OneTimeTokenAccount) acc)
                    .findFirst();

            if (accountOpt.isEmpty()) {
                return ValidationResult.error(HttpStatus.BAD_REQUEST, "device not found");
            }

            OneTimeTokenAccount account = accountOpt.get();

            // Check OTP
            if (!validateOtp(account, Integer.parseInt(otp))) {
                return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid OTP");
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

            Optional<? extends OneTimeTokenAccount> accountOpt = temporaryAccountStorage.findBySecret(encodedSecret);

            // If not found in temporary storage, search in the main repository
            if (accountOpt.isEmpty()) {
                accountOpt = tokenCredentialRepository.load().stream()
                        .filter(acc -> encodedSecret.equals(acc.getSecretKey()))
                        .findFirst();
            }

            if (accountOpt.isEmpty()) {
                return ValidationResult.error(HttpStatus.FORBIDDEN, "didnt found account with this secret key");
            }

            OneTimeTokenAccount account = accountOpt.get();

            // Check initialCode
            if (!validateOtp(InalogyAuthenticatorAccount.from(account), Integer.parseInt(initialCode))) {
                temporaryAccountStorage.updateRegistrationStatus(account.getId(), "REJECTED");
                return ValidationResult.error(HttpStatus.FORBIDDEN, "otp registration data is invalid");
            }

            // Update account with device data
            temporaryAccountStorage.updateAccount(account.getId(), pushId, deviceKeyId, deviceType, deviceName);

            InalogyAuthenticatorAccount inalogyAccount = InalogyAuthenticatorAccount.from(account);
            inalogyAccount.setPushId(pushId);
            inalogyAccount.setDeviceKeyId(deviceKeyId);
            inalogyAccount.setDeviceType(deviceType);
            inalogyAccount.setName(deviceName);
            tokenCredentialRepository.update(inalogyAccount);

            LOGGER.debug("Registered push device for user: [{}], device: [{}]", account.getUsername(), deviceName);

            return ValidationResult.success();
        } catch (Exception e) {
            LOGGER.error("Error registering push device", e);
            return ValidationResult.error(HttpStatus.INTERNAL_SERVER_ERROR, "internal server error");
        }
    }
}
