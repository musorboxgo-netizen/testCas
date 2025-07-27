package cz.ami.cas.inauth.configuration.mfa;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apereo.cas.configuration.model.core.util.EncryptionRandomizedCryptoProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Getter
@Setter
@Accessors(chain = true)
public class InalogyAuthenticatorMultifactorScratchCodeProperties {

    @NestedConfigurationProperty
    private EncryptionRandomizedCryptoProperties encryption = new EncryptionRandomizedCryptoProperties();

    private int number = 5;
}
