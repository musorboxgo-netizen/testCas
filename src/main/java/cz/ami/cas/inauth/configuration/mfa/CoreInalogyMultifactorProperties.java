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
    @RequiredProperty
    private String issuer = "CASIssuer";

    /**
     * Label used in the barcode when dealing with device registration events.
     * Used in the registration URL to identify CAS.
     */
    @RequiredProperty
    private String label = "CASLabel";

    private String callbackUrl;

    private String hmacHashFunction = "HmacSHA1";

    private KeyRepresentation keyRepresentation = BASE32;

    /**
     * Length of the generated code.
     */
    private int codeDigits = 6;

    private int keyModulus = (int) Math.pow(10, codeDigits);

    private int secretKeySize = 160;

    /**
     * The expiration time of the generated code in seconds.
     */
    private long timeStepSize = 30;

    /**
     * Since TOTP passwords are time-based, it is essential that the clock of both the server and
     * the client are synchronised within
     * the tolerance defined here as the window size.
     */
    private int windowSize = 3;

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

    @NestedConfigurationProperty
    private InalogyAuthenticatorMultifactorScratchCodeProperties scratchCodes =
            new InalogyAuthenticatorMultifactorScratchCodeProperties();
}