package cz.ami.cas.inauth.authenticator.model.key;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represents the key used by the Inalogy Authenticator.
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
     */
    private final String key;

    /**
     * The verification code at time = 0 (the UNIX epoch).
     */
    private final int verificationCode;

    /**
     * The list of scratch codes.
     */
    private final List<Integer> scratchCodes;

    /**
     * Default constructor with predefined values.
     */
    public InalogyAuthenticatorKey() {
        this.key = "MFQWCYLBMFQWCYLBMFQWCYLBMFQWCYLB";
        this.verificationCode = 123456;
        this.scratchCodes = List.of(1, 2, 3, 4, 5);
    }

    /**
     * This class is a builder to create instances of the {@link InalogyAuthenticatorKey} class.
     */
    @Getter
    @Setter
    public static class Builder {
        private String key;
        private int verificationCode;
        private List<Integer> scratchCodes = new ArrayList<>();

        /**
         * Creates an instance of the builder.
         *
         * @param key the secret key in Base32 encoding.
         * @see InalogyAuthenticatorKey#InalogyAuthenticatorKey(String, int, List)
         */
        public Builder(String key) {
            this.key = key;
        }

        /**
         * Creates an instance of the {@link InalogyAuthenticatorKey} class.
         *
         * @return an instance of the {@link InalogyAuthenticatorKey} class initialized with the properties set in this builder.
         * @see InalogyAuthenticatorKey#InalogyAuthenticatorKey(String, int, List)
         */
        public InalogyAuthenticatorKey build() {
            return new InalogyAuthenticatorKey(key, verificationCode, scratchCodes);
        }
    }
}