package cz.ami.cas.inauth.configuration.mfa;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
public class InalogyMessagingServiceProperties {
    private boolean test = true;
    private String messagingServiceUrl = "http://localhost:8080/api";
    private String apiKey;
}
