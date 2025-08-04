package cz.ami.cas.inauth.configuration.mfa;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apereo.cas.configuration.model.core.util.EncryptionRandomizedCryptoProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Configuration properties for scratch codes in Inalogy multifactor authentication.
 * Scratch codes are one-time use backup codes that can be used when the primary
 * authentication method (like TOTP) is unavailable.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Getter
@Setter
@Accessors(chain = true)
public class InalogyAuthenticatorMultifactorScratchCodeProperties {

    /**
     * Encryption properties for securing scratch codes.
     * Uses randomized encryption to protect the codes at rest.
     */
    @NestedConfigurationProperty
    private EncryptionRandomizedCryptoProperties encryption = new EncryptionRandomizedCryptoProperties();

    /**
     * The number of scratch codes to generate for each account.
     * Default is 5 codes per account.
     */
    private int number = 5;
}
