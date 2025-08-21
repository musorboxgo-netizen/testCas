package cz.ami.cas.inauth.configuration.mfa;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apereo.cas.configuration.model.core.util.EncryptionJwtCryptoProperties;
import org.apereo.cas.configuration.model.core.util.EncryptionJwtSigningJwtCryptographyProperties;
import org.apereo.cas.configuration.model.core.util.SigningJwtCryptoProperties;
import org.apereo.cas.configuration.model.support.mfa.BaseMultifactorAuthenticationProviderProperties;
import org.apereo.cas.configuration.model.support.mfa.gauth.JpaGoogleAuthenticatorMultifactorProperties;
import org.apereo.cas.configuration.model.support.mfa.gauth.JsonGoogleAuthenticatorMultifactorProperties;
import org.apereo.cas.configuration.model.support.quartz.ScheduledJobProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.io.Serial;

/**
 * Configuration properties for Inalogy Authenticator multifactor authentication.
 * This class extends the base multifactor authentication provider properties
 * and adds Inalogy-specific configuration options.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "ami.inalogy.mfa")
@Accessors(chain = true)
public class InalogyAuthenticatorMultifactorProperties extends BaseMultifactorAuthenticationProviderProperties {

    /**
     * Provider id by default.
     */
    public static final String DEFAULT_IDENTIFIER = "mfa-inalogy";

    private boolean enabled = false;

    @Serial
    private static final long serialVersionUID = 6651799933245790819L;

    /**
     * Core/common settings for Inalogy Multifactor authentication.
     */
    @NestedConfigurationProperty
    private CoreInalogyMultifactorProperties core = new CoreInalogyMultifactorProperties();

    /**
     * Cryptography settings for JWT encryption and signing.
     * Used for secure token generation and validation.
     */
    @NestedConfigurationProperty
    private EncryptionJwtSigningJwtCryptographyProperties crypto = new EncryptionJwtSigningJwtCryptographyProperties();

    @NestedConfigurationProperty
    private JsonInalogyAuthenticatorMultifactorProperties json = new JsonInalogyAuthenticatorMultifactorProperties();

    @NestedConfigurationProperty
    private JpaInalogyAuthenticatorMultifactorProperties jpa = new JpaInalogyAuthenticatorMultifactorProperties();

    @NestedConfigurationProperty
    private InalogyAuthenticatorDownloadProperties download = new InalogyAuthenticatorDownloadProperties();

    /**
     * Scheduled job properties for the cleaner task.
     * Configures when and how often expired tokens and records are cleaned up.
     */
    @NestedConfigurationProperty
    private ScheduledJobProperties cleaner = new ScheduledJobProperties();

    /**
     * Configuration properties for the Inalogy messaging service.
     * Used for push notifications and other communication with user devices.
     */
    @NestedConfigurationProperty
    private InalogyMessagingServiceProperties messagingService = new InalogyMessagingServiceProperties();

    /**
     * Constructor that initializes the properties with default values.
     * Sets the provider ID, crypto key sizes, and cleaner schedule.
     */
    public InalogyAuthenticatorMultifactorProperties() {
        setId(DEFAULT_IDENTIFIER);
        crypto.getEncryption().setKeySize(EncryptionJwtCryptoProperties.DEFAULT_STRINGABLE_ENCRYPTION_KEY_SIZE);
        crypto.getSigning().setKeySize(SigningJwtCryptoProperties.DEFAULT_STRINGABLE_SIGNING_KEY_SIZE);
        cleaner.getSchedule().setEnabled(true).setStartDelay("PT1M").setRepeatInterval("PT1M");
    }
}
