package cz.ami.cas.inauth.configuration.mfa;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apereo.cas.configuration.support.RequiredProperty;

/**
 * Configuration properties for the Inalogy messaging service.
 * This service is used for sending push notifications and other
 * communications to user devices during the authentication process.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Getter
@Setter
@Accessors(chain = true)
public class InalogyMessagingServiceProperties {

    /**
     * The base URL of the messaging service API.
     */
    @RequiredProperty
    private String url;

    /**
     * The API key used for authentication with the messaging service.
     * This key must be provided for production use.
     */
    @RequiredProperty
    private String apiKey;
}
