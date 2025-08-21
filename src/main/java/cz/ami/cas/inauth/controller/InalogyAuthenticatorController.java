package cz.ami.cas.inauth.controller;

import cz.ami.cas.inauth.configuration.mfa.InalogyAuthenticatorDownloadProperties;
import cz.ami.cas.inauth.service.IInalogyAuthenticator;
import cz.ami.cas.inauth.authenticator.model.push.ValidationResult;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Map;

/**
 * This is {@link InalogyAuthenticatorController}.
 * Controller for generating and displaying QR codes for Inalogy Authenticator.
 * Also provides endpoints for push authentication as per the requirements.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Controller
@RequiredArgsConstructor
@RequestMapping("/inalogy")
@Slf4j
public class InalogyAuthenticatorController {

    private final IInalogyAuthenticator inalogyAuthenticator;

    private final InalogyAuthenticatorDownloadProperties downloadProperties;

    /**
     * Request body for device registration.
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SubmitRequest {
        private String deviceName;
        private String pushId;
        private String deviceKeyId;
        private String encodedSecret;
        private String deviceType;
        private String initialCode;
    }

    /**
     * Request body for push authentication validation.
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ValidateRequest {
        private String pushId;
        private String otp;
        private String challengeResponse;
    }

    /**
     * Request body for push authentication termination.
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TerminateRequest {
        private String pushId;
        private String otp;
    }

    /**
     * Request body for push ID change.
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PushIdChangeRequest {
        private String deviceKey;
        private String pushId;
        private String otp;
    }

    /**
     * Error response.
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ErrorResponse {
        private String error;
    }


    @GetMapping("/check/login")
    public ResponseEntity<Map<String, String>> checkLoginStatus(@RequestParam("pushId") String pushId) {
        var status = inalogyAuthenticator.checkPushAuthenticationStatus(pushId);
        LOGGER.debug("Received check mfa login status request.");
        return ResponseEntity.ok(Map.of("status", status.name()));
    }

    @GetMapping("/check/registration")
    public ResponseEntity<Map<String, String>> checkRegistrationStatus(@RequestParam("requestId") String requestId) {
        var status = inalogyAuthenticator.checkPushRegistrationStatus(requestId);
        LOGGER.debug("Received check mfa registration status request.");
        return ResponseEntity.ok(Map.of("status", status.name()));
    }

    @GetMapping("/qr-redirect")
    public ResponseEntity<Void> checkQrRedirectStatus(HttpServletRequest request,
                                                      @RequestParam(required = false) String os) {
        String ua = request.getHeader("User-Agent");
        String target = null;

        if ("ios".equalsIgnoreCase(os))      target = downloadProperties.getAppStoreAppUrl();
        else if ("android".equalsIgnoreCase(os)) target = downloadProperties.getGooglePlayAppUrl();

        if (target == null && ua != null) {
            String lua = ua.toLowerCase();
            if (lua.contains("iphone") || lua.contains("ipad") || lua.contains("ipod") || lua.contains("ios")) {
                target = downloadProperties.getAppStoreAppUrl();
            } else if (lua.contains("android")) {
                target = downloadProperties.getGooglePlayAppUrl();
            }
        }
        if (target == null) {
            return ResponseEntity.status(204).build();
        }
        var location = URI.create(target);
        return ResponseEntity.status(302).location(location).build();
    }

    /**
     * Registers a new push authentication device for the user.
     * This endpoint is used during the initial setup of push authentication.
     *
     * @param request The submit mfa containing device information
     * @return ResponseEntity with no content if successful, or error response
     */
    @PostMapping("/submit")
    public ResponseEntity<?> submit(@RequestBody SubmitRequest request) {
        LOGGER.debug("Received submit mfa: [{}]", request);

        // Validate mfa
        if (request.getDeviceName() == null || request.getPushId() == null ||
                request.getDeviceKeyId() == null || request.getEncodedSecret() == null ||
                request.getDeviceType() == null || request.getInitialCode() == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("one or more data field for push registration are blank"));
        }

        // Validate device type
        if (!request.getDeviceType().equals("IOS") && !request.getDeviceType().equals("ANDROID")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("invalid device type"));
        }

        // Register device
        ValidationResult result = inalogyAuthenticator.registerPushDevice(
                request.getEncodedSecret(),
                request.getDeviceName(),
                request.getPushId(),
                request.getDeviceKeyId(),
                request.getDeviceType(),
                request.getInitialCode()
        );

        if (!result.isSuccess()) {
            return ResponseEntity.status(result.getStatus())
                    .body(new ErrorResponse(result.getErrorMessage()));
        }

        // Return success response
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    /**
     * Validates a push authentication challenge response.
     * This endpoint is called when the user responds to a push notification challenge.
     *
     * @param request The validate mfa containing the challenge response
     * @return ResponseEntity with no content if successful, or error response
     */
    @PostMapping("/validate")
    public ResponseEntity<?> validate(@RequestBody ValidateRequest request) {
        LOGGER.debug("Received validate mfa: [{}]", request);

        // Validate mfa
        if (request.getPushId() == null || request.getOtp() == null || request.getChallengeResponse() == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("one or more data field for push validation are blank"));
        }



        ValidationResult result = inalogyAuthenticator.validatePushAuthentication(
                request.getPushId(),
                request.getOtp(),
                request.getChallengeResponse()
        );

        if (!result.isSuccess()) {
            return ResponseEntity.status(result.getStatus())
                    .body(new ErrorResponse(result.getErrorMessage()));
        }

        // Return success response
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    /**
     * Terminates an active push authentication session.
     * This endpoint is used to cancel or end a push authentication process.
     *
     * @param request The terminate mfa
     * @return ResponseEntity with no content if successful, or error response
     */
    @PostMapping("/terminate")
    public ResponseEntity<?> terminate(@RequestBody TerminateRequest request) {
        LOGGER.debug("Received terminate mfa: [{}]", request);

        // Validate mfa
        if (request.getPushId() == null || request.getOtp() == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("one or more data field for push termination are blank"));
        }

        ValidationResult result = inalogyAuthenticator.terminatePushAuthentication(
                request.getPushId(),
                request.getOtp()
        );

        if (!result.isSuccess()) {
            return ResponseEntity.status(result.getStatus())
                    .body(new ErrorResponse(result.getErrorMessage()));
        }

        // Return success response
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    /**
     * Updates the push ID for an existing device.
     * This is useful when the device's push notification token changes.
     *
     * @param request The push ID change mfa
     * @return ResponseEntity with no content if successful, or error response
     */
    @PostMapping("/push-id-change")
    public ResponseEntity<?> pushIdChange(@RequestBody PushIdChangeRequest request) {
        LOGGER.debug("Received push ID change mfa: [{}]", request);

        // Validate mfa
        if (request.getDeviceKey() == null || request.getPushId() == null || request.getOtp() == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("one or more data field for push ID change are blank"));
        }

        // Update the pushId
        ValidationResult result = inalogyAuthenticator.updatePushId(
                request.getDeviceKey(),
                request.getPushId(),
                request.getOtp()
        );

        if (!result.isSuccess()) {
            return ResponseEntity.status(result.getStatus())
                    .body(new ErrorResponse(result.getErrorMessage()));
        }

        // Return success response
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

}
