package cz.ami.cas.inauth.service;

import cz.ami.cas.inauth.configuration.mfa.InalogyMessagingServiceProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class InalogyMessagingService {

    private final RestTemplate restTemplate = new RestTemplate();

    private final InalogyMessagingServiceProperties properties;

    /**
     * Send a push notification to the user's device.
     *
     * @param deviceId The device ID to send the notification to
     * @param deviceType The device type (IOS or ANDROID)
     * @param challengeType The type of challenge (CHALLENGE_APPROVE, CHALLENGE_WRITE, CHALLENGE_CHOOSE)
     * @param dataForChallenge Data for the challenge (depends on challenge type)
     * @param keyId Unique identifier for this authentication attempt
     * @param callback Callback URL for the mobile app to respond to
     * @return true if the notification was sent successfully, false otherwise
     */
    public boolean sendPushNotification(String deviceId, String deviceType,
                                        String challengeType, String dataForChallenge,
                                        String keyId, String callback) {
        try {
            if(properties.isTest()) return true;

            val endpoint = properties.getMessagingServiceUrl() + "/v1/push-notification/send";

            HttpHeaders headers = new HttpHeaders();
            val apiKey = properties.getApiKey();
            headers.set("X-API-KEY", apiKey);
            headers.set("Content-Type", "application/json");

            // Create serialized data
            long validUntil = Instant.now().plusSeconds(300).getEpochSecond(); // 5 minutes validity
            String serializedData = String.format(
                    "{\"pushType\":\"%s\",\"dataForChallenge\":\"%s\",\"keyId\":\"%s\",\"callback\":\"%s\",\"validUntil\":%d}",
                    challengeType, dataForChallenge, keyId, callback, validUntil
            );

            // Create request body
            String requestBody = String.format(
                    "{\"deviceId\":\"%s\",\"deviceType\":\"%s\",\"title\":\"Authentication required\",\"body\":\"Verify your identity to continue.\",\"sound\":\"default\",\"serializedData\":\"%s\"}",
                    deviceId, deviceType, serializedData.replace("\"", "\\\"")
            );

            HttpEntity<String> request = new HttpEntity<>(requestBody, headers);
            ResponseEntity<Void> response = restTemplate.postForEntity(endpoint, request, Void.class);

            return response.getStatusCode() == HttpStatus.NO_CONTENT;
        } catch (Exception e) {
            LOGGER.error("Failed to send push notification", e);
            return false;
        }
    }
}
