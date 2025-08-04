package cz.ami.cas.inauth.configuration.mfa;


import cz.ami.cas.inauth.authenticator.model.key.KeyRepresentation;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apereo.cas.configuration.support.RequiredProperty;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.io.Serial;
import java.io.Serializable;

import static cz.ami.cas.inauth.authenticator.model.key.KeyRepresentation.*;

/**
 * Core configuration properties for Inalogy multifactor authentication.
 * This class contains all the basic settings needed for the Inalogy authenticator
 * to function, including TOTP settings, device registration options, and scratch codes.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Getter
@Setter
@Accessors(chain = true)
public class CoreInalogyMultifactorProperties implements Serializable {

    @Serial
    private static final long serialVersionUID = -7451748853833491119L;

    /**
     * Issuer used in the barcode when dealing with device registration events.
     * Used in the registration URL to identify CAS.
     */
    private String issuer = "CASIssuer";

    /**
     * Label used in the barcode when dealing with device registration events.
     * Used in the registration URL to identify CAS.
     */
    private String label = "CASLabel";

    /**
     * URL to which the system will redirect after successful authentication.
     */
    private String callbackUrl;

    /**
     * The HMAC hash function used for generating TOTP codes.
     * Default is HmacSHA1.
     */
    private String hmacHashFunction = "HmacSHA256";

    /**
     * The type of challenge to present during authentication.
     * Default is "CHALLENGE_WRITE".
     */
    private String challengeType = "CHALLENGE_WRITE";

    /**
     * The representation format for the secret key.
     * Default is BASE32.
     */
    private KeyRepresentation keyRepresentation = BASE32;

    /**
     * Length of the generated code.
     */
    private int codeDigits = 6;

    /**
     * The modulus used to calculate the verification code.
     * Derived from the number of code digits.
     */
    private int keyModulus = (int) Math.pow(10, codeDigits);

    /**
     * The size of the secret key in bits.
     * Default is 160 bits.
     */
    private int secretKeySize = 160;

    /**
     * Since TOTP passwords are time-based, it is essential that the clock of both the server and
     * the client are synchronised within
     * the tolerance defined here as the window size.
     */
    private int windowSize = 3;

    /**
     * The expiration time of the generated code in seconds.
     */
    private long timeStepSize = 30;

    /**
     * When enabled, allows the user/system to accept multiple accounts
     * and device registrations per user, allowing one to switch between
     * or register new devices/accounts automatically.
     */
    private boolean multipleDeviceRegistrationEnabled;

    /**
     * When enabled, allows the user/system to register accounts
     * and devices.
     */
    private boolean deviceRegistrationEnabled = true;

    /**
     * Indicates whether this provider should support trusted devices.
     */
    private boolean trustedDeviceEnabled = true;

    private boolean testMode = false;

    @NestedConfigurationProperty
    private InalogyAuthenticatorMultifactorScratchCodeProperties scratchCodes =
            new InalogyAuthenticatorMultifactorScratchCodeProperties();
}
