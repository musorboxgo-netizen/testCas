package cz.ami.cas.inauth.configuration.mfa;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apereo.cas.configuration.model.core.util.EncryptionJwtCryptoProperties;
import org.apereo.cas.configuration.model.core.util.EncryptionJwtSigningJwtCryptographyProperties;
import org.apereo.cas.configuration.model.core.util.SigningJwtCryptoProperties;
import org.apereo.cas.configuration.model.support.mfa.BaseMultifactorAuthenticationProviderProperties;
import org.apereo.cas.configuration.model.support.quartz.ScheduledJobProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.io.Serial;

@Getter
@Setter
@Accessors(chain = true)
public class InalogyAuthenticatorMultifactorProperties extends BaseMultifactorAuthenticationProviderProperties {

    /**
     * Provider id by default.
     */
    public static final String DEFAULT_IDENTIFIER = "mfa-inalogy";

    @Serial
    private static final long serialVersionUID = 6651799933245790819L;

    /**
     * Core/common settings for Inalogy Multifactor authentication.
     */
    @NestedConfigurationProperty
    private CoreInalogyMultifactorProperties core = new CoreInalogyMultifactorProperties();

    @NestedConfigurationProperty
    private EncryptionJwtSigningJwtCryptographyProperties crypto = new EncryptionJwtSigningJwtCryptographyProperties();

    @NestedConfigurationProperty
    private ScheduledJobProperties cleaner = new ScheduledJobProperties();

    @NestedConfigurationProperty
    private InalogyMessagingServiceProperties messagingService = new InalogyMessagingServiceProperties();

    public InalogyAuthenticatorMultifactorProperties() {
        setId(DEFAULT_IDENTIFIER);
        crypto.getEncryption().setKeySize(EncryptionJwtCryptoProperties.DEFAULT_STRINGABLE_ENCRYPTION_KEY_SIZE);
        crypto.getSigning().setKeySize(SigningJwtCryptoProperties.DEFAULT_STRINGABLE_SIGNING_KEY_SIZE);
        cleaner.getSchedule().setEnabled(true).setStartDelay("PT1M").setRepeatInterval("PT1M");
    }
}
