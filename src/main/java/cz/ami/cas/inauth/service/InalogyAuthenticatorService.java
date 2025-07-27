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
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.springframework.http.HttpStatus;

import java.util.*;
import java.util.stream.Collectors;

/**
 * This is {@link InalogyAuthenticatorService}.
 * Implementation of the IInalogyAuthenticator interface that works directly with
 * InalogyAuthenticatorToken, InalogyAuthenticatorAccount, and other related classes.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Slf4j
@Getter
@Setter
public class InalogyAuthenticatorService implements IInalogyAuthenticator {
    private final CoreInalogyMultifactorProperties properties;
    private final OneTimeTokenCredentialRepository tokenCredentialRepository;
    private final IInalogyPushAuthenticationRepository pushAuthenticationRepository;
    private final InalogyMessagingService messagingService;
    private final TemporaryAccountStorage temporaryAccountStorage;
    private InalogyOtpService otpService;

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

    @Override
    public InalogyAuthenticatorKey createCredentials() {
//        String generatedKey = "JBSWY3DPEHPK3PXP";
//
//        int validationCode = 123456;
//
//        List<Integer> scratchCodes = Arrays.asList(1234, 5678, 9012, 3456, 7890);
//
//        return new InalogyAuthenticatorKey(secretKey, verificationCode, scratchCodes);

        // Extracting the bytes making up the secret key.
        byte[] secretKey = otpService.generateSecretBytes();
        String generatedKey = otpService.calculateSecretKey(secretKey);

        // Generating the verification code at time = 0.
        int validationCode = otpService.calculateValidationCode(secretKey);

        // Calculate scratch codes
        List<Integer> scratchCodes = otpService.calculateScratchCodes();

        return new InalogyAuthenticatorKey(generatedKey, validationCode, scratchCodes);
    }


    public Optional<InalogyAuthenticatorAccount> findAccountByPushId(String pushId) {
        return tokenCredentialRepository.load().stream()
                .filter(acc -> acc instanceof InalogyAuthenticatorAccount)
                .map(acc -> (InalogyAuthenticatorAccount) acc)
                .filter(acc -> pushId.equals(acc.getDeviceId()))
                .findFirst();
    }

    @Override
    public boolean validateOtp(OneTimeTokenAccount account, int token) {
        try {
            return otpService.checkCode(account.getSecretKey(), token, new Date().getTime());
        } catch (NumberFormatException e) {
            LOGGER.warn("Invalid OTP format: [{}]", token);
            return false;
        }
    }


    /**
     * Находит активные запросы аутентификации для пользователя.
     *
     * @param username имя пользователя
     * @return список активных запросов аутентификации
     */
    public List<PendingPushAuthentication> findActivePendingAuthentications(String username) {
        return pushAuthenticationRepository.findByUsername(username).stream()
                .filter(auth -> !auth.isResponded() && !auth.isExpired())
                .collect(Collectors.toList());
    }

    /**
     * Находит последний активный запрос аутентификации для пользователя.
     *
     * @param username имя пользователя
     * @return Optional с найденным запросом или пустой Optional
     */
    public Optional<PendingPushAuthentication> findLatestPendingAuthentication(String username) {
        return findActivePendingAuthentications(username).stream()
                .max(Comparator.comparing(PendingPushAuthentication::getCreatedAt));
    }

    /**
     * Инициирует push-аутентификацию для пользователя.
     *
     * @param username        имя пользователя
     * @param callbackBaseUrl базовый URL для callback
     * @return keyId созданного запроса или null в случае ошибки
     */
    @Override
    public String initiatePushAuthentication(String username, String callbackBaseUrl) {
        try {
            // Находим устройство пользователя
            val accounts = tokenCredentialRepository.get(username);
            if (accounts == null || accounts.isEmpty()) {
                LOGGER.warn("No accounts found for user: [{}]", username);
                return null;
            }

            // Находим устройство с поддержкой push
            Optional<InalogyAuthenticatorAccount> pushAccountOpt = accounts.stream()
                    .filter(acc -> acc instanceof InalogyAuthenticatorAccount)
                    .map(acc -> (InalogyAuthenticatorAccount) acc)
                    .filter(acc -> acc.getDeviceId() != null && !acc.getDeviceId().isEmpty())
                    .findFirst();

            if (pushAccountOpt.isEmpty()) {
                LOGGER.warn("No push-enabled device found for user: [{}]", username);
                return null;
            }

            val pushAccount = pushAccountOpt.get();

            // Генерируем уникальный keyId
            String keyId = UUID.randomUUID().toString();

            // Выбираем тип вызова и генерируем данные
            String challengeType;
            String dataForChallenge;
            Random random = new Random();
            int challengeTypeIndex = random.nextInt(3);

            switch (challengeTypeIndex) {
                case 0:
                    challengeType = "CHALLENGE_APPROVE";
                    dataForChallenge = "";
                    break;
                case 1:
                    challengeType = "CHALLENGE_WRITE";
                    dataForChallenge = String.valueOf(10000 + random.nextInt(90000));
                    break;
                case 2:
                default:
                    challengeType = "CHALLENGE_CHOOSE";
                    int num1 = random.nextInt(100);
                    int num2 = random.nextInt(100);
                    int num3 = random.nextInt(100);
                    dataForChallenge = num1 + "," + num2 + "," + num3;
                    break;
            }

            // Формируем callback URL
            String callback = callbackBaseUrl + "/inalogy/callback/" + username;

            // Создаем запись о ожидающей аутентификации
            val pendingAuth = new PendingPushAuthentication(
                    keyId, username, challengeType, dataForChallenge, 300
            );

            // Сохраняем запись
            pushAuthenticationRepository.save(pendingAuth);

            // Отправляем push-уведомление
            boolean sent = messagingService.sendPushNotification(
                    pushAccount.getDeviceId(),
                    pushAccount.getDeviceType(),
                    challengeType,
                    dataForChallenge,
                    keyId,
                    callback
            );

            if (!sent) {
                LOGGER.error("Failed to send push notification for user: [{}]", username);
                pushAuthenticationRepository.remove(keyId);
                return null;
            }

            LOGGER.debug("Initiated push authentication for user: [{}], keyId: [{}]", username, keyId);
            return keyId;
        } catch (Exception e) {
            LOGGER.error("Error initiating push authentication for user: [{}]", username, e);
            return null;
        }
    }

    /**
     * Проверяет статус push-аутентификации.
     *
     * @param keyId идентификатор запроса
     * @return статус аутентификации
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
     * Проверяет ответ на вызов в зависимости от типа вызова.
     *
     * @param challengeType     тип вызова
     * @param dataForChallenge  данные для вызова
     * @param challengeResponse ответ на вызов
     * @return true если ответ верный, иначе false
     */
    @Override
    public boolean validateChallengeResponse(String challengeType, String dataForChallenge, String challengeResponse) {
        switch (challengeType) {
            case "CHALLENGE_APPROVE":
                return "true".equals(challengeResponse);

            case "CHALLENGE_WRITE":
                return dataForChallenge.equals(challengeResponse);

            case "CHALLENGE_CHOOSE":
                String[] options = dataForChallenge.split(",");
                for (String option : options) {
                    if (option.equals(challengeResponse)) {
                        return true;
                    }
                }
                return false;

            default:
                LOGGER.warn("Unknown challenge type: [{}]", challengeType);
                return false;
        }
    }

    /**
     * Валидирует ответ на push-аутентификацию.
     *
     * @param pushId            идентификатор устройства
     * @param otp               OTP код
     * @param challengeResponse ответ на вызов
     * @return результат валидации с информацией об ошибке или успехе
     */
    @Override
    public ValidationResult validatePushAuthentication(String pushId, String otp, String challengeResponse) {
        // Находим учетную запись по pushId
        Optional<InalogyAuthenticatorAccount> accountOpt = findAccountByPushId(pushId);
        if (accountOpt.isEmpty()) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "device not found");
        }

        // Проверяем OTP
        InalogyAuthenticatorAccount account = accountOpt.get();
        if (!validateOtp(account, Integer.parseInt(otp))) {
            return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid OTP");
        }

        // Находим последний активный запрос аутентификации
        Optional<PendingPushAuthentication> pendingAuthOpt = findLatestPendingAuthentication(account.getUsername());
        if (pendingAuthOpt.isEmpty()) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "authentication request not found");
        }

        PendingPushAuthentication pendingAuth = pendingAuthOpt.get();

        // Проверяем ответ на вызов
        boolean isValidChallengeResponse = validateChallengeResponse(
                pendingAuth.getChallengeType(),
                pendingAuth.getDataForChallenge(),
                challengeResponse
        );

        if (!isValidChallengeResponse) {
            return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid challenge response");
        }

        // Обновляем статус аутентификации
        pushAuthenticationRepository.updateResponse(pendingAuth.getKeyId(), true);

        return ValidationResult.success();
    }

    /**
     * Терминирует активные запросы аутентификации.
     *
     * @param pushId идентификатор устройства
     * @param otp    OTP код
     * @return результат операции с информацией об ошибке или успехе
     */
    @Override
    public ValidationResult terminatePushAuthentication(String pushId, String otp) {
        // Находим учетную запись по pushId
        Optional<InalogyAuthenticatorAccount> accountOpt = findAccountByPushId(pushId);
        if (accountOpt.isEmpty()) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "device not found");
        }

        // Проверяем OTP
        InalogyAuthenticatorAccount account = accountOpt.get();
        if (!validateOtp(account, Integer.parseInt(otp))) {
            return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid OTP");
        }

        // Находим активные аутентификации
        List<PendingPushAuthentication> activeAuths = findActivePendingAuthentications(account.getUsername());
        if (activeAuths.isEmpty()) {
            return ValidationResult.error(HttpStatus.BAD_REQUEST, "no active authentication requests found");
        }

        // Отклоняем все активные аутентификации
        for (PendingPushAuthentication auth : activeAuths) {
            pushAuthenticationRepository.updateResponse(auth.getKeyId(), false);
        }

        return ValidationResult.success();
    }

    /**
     * Обновляет pushId для устройства.
     *
     * @param deviceKey идентификатор ключа устройства
     * @param newPushId новый идентификатор для push-уведомлений
     * @param otp       OTP код
     * @return результат операции с информацией об ошибке или успехе
     */
    @Override
    public ValidationResult updatePushId(String deviceKey, String newPushId, String otp) {
        try {
            // Находим устройство по deviceKey
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

            // Проверяем OTP
            if (!validateOtp(account, Integer.parseInt(otp))) {
                return ValidationResult.error(HttpStatus.FORBIDDEN, "invalid OTP");
            }

            // Обновляем pushId
            InalogyAuthenticatorAccount inalogyAccount = InalogyAuthenticatorAccount.from(account);
            inalogyAccount.setDeviceId(newPushId);

            tokenCredentialRepository.update(inalogyAccount);
            LOGGER.debug("Updated push ID for user: [{}], device key: [{}]", account.getUsername(), deviceKey);

            return ValidationResult.success();
        } catch (Exception e) {
            LOGGER.error("Error updating push ID", e);
            return ValidationResult.error(HttpStatus.INTERNAL_SERVER_ERROR, "internal server error");
        }
    }

    /**
     * Регистрирует устройство для push-аутентификации.
     *
     * @param encodedSecret секретный ключ
     * @param deviceName    имя устройства
     * @param pushId        идентификатор устройства для push-уведомлений
     * @param deviceKeyId   идентификатор ключа устройства
     * @param deviceType    тип устройства (IOS/ANDROID)
     * @param initialCode   начальный OTP код для проверки
     * @return результат операции с информацией об ошибке или успехе
     */
    @Override
    public ValidationResult registerPushDevice(String encodedSecret, String deviceName,
                                               String pushId, String deviceKeyId,
                                               String deviceType, String initialCode) {
        try {

            Optional<? extends OneTimeTokenAccount> accountOpt = temporaryAccountStorage.findBySecret(encodedSecret);

            // Если не нашли во временном хранилище, ищем в основном репозитории
            if (accountOpt.isEmpty()) {
                accountOpt = tokenCredentialRepository.load().stream()
                        .filter(acc -> encodedSecret.equals(acc.getSecretKey()))
                        .findFirst();
            }

            if (accountOpt.isEmpty()) {
                return ValidationResult.error(HttpStatus.FORBIDDEN, "didnt found account with this secret key");
            }

            OneTimeTokenAccount account = accountOpt.get();

            // Проверяем initialCode
            if (!validateOtp(InalogyAuthenticatorAccount.from(account), Integer.parseInt(initialCode))) {
                temporaryAccountStorage.updateRegistrationStatus(account.getId(), "REJECTED");
                return ValidationResult.error(HttpStatus.FORBIDDEN, "otp registration data is invalid");
            }

            // Обновляем учетную запись с данными устройства
            temporaryAccountStorage.updateAccount(account.getId(), pushId, deviceKeyId, deviceType, deviceName);

            InalogyAuthenticatorAccount inalogyAccount = InalogyAuthenticatorAccount.from(account);
            inalogyAccount.setDeviceId(pushId);
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