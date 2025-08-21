package cz.ami.cas.inauth.authenticator.model.key;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represents the key used by the Inalogy Authenticator.
 * It contains the secret key, verification code, and scratch codes needed
 * for multi-factor authentication operations.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Getter
@Setter
@RequiredArgsConstructor
public final class InalogyAuthenticatorKey {
    /**
     * The secret key in Base32 encoding.
     * This key is used to generate time-based one-time passwords (TOTP).
     */
    private final String key;

    /**
     * The verification code at time = 0 (the UNIX epoch).
     * This is used as a reference point for time-based code generation.
     */
    private final int verificationCode;

    /**
     * The list of scratch codes.
     * These are backup codes that can be used for authentication when
     * the primary authentication method is unavailable.
     */
    private final List<Integer> scratchCodes;
}
