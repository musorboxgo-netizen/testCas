package cz.ami.cas.inauth.configuration.mfa;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
public class InalogyMessagingServiceProperties {
    private boolean test = false;
    private String messagingServiceUrl = "https://ims.inalogy.com/api/v1/push-notification/send";
    private String apiKey = "�!Y�	��\�2|GDE��r]\R�N�z";
}
