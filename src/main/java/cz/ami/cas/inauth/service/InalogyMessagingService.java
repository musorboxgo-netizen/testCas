package cz.ami.cas.inauth.service;

import cz.ami.cas.inauth.configuration.mfa.InalogyMessagingServiceProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;

/**
 * Service for sending push notifications to user devices.
 * This service handles the communication with the messaging API to deliver
 * authentication challenges and notifications to mobile devices.
 *
 * @since 1.0.0
 */

@RequiredArgsConstructor
@Slf4j
public class InalogyMessagingService {

    HttpClient httpClient = HttpClient.newHttpClient();

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

            val endpoint = properties.getUrl();

            HttpHeaders headers = new HttpHeaders();
            val apiKey = properties.getApiKey();
            headers.set("X-API-KEY", apiKey);
            headers.setContentType(MediaType.APPLICATION_JSON);

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

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(endpoint))
                    .header("X-API-KEY", apiKey)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());


            return response.statusCode() == 204;
        } catch (Exception e) {
            LOGGER.error("Failed to send push notification", e);
            return false;
        }
    }
}
