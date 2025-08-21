package cz.ami.cas.inauth.service;

import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

/**
 * Service for One-Time Password (OTP) operations.
 * This service provides functionality for generating, validating, and managing
 * time-based one-time passwords (TOTP) and scratch codes used in multi-factor
 * authentication.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@RequiredArgsConstructor
@Slf4j
public class InalogyOtpService {
    /**
     * Configuration properties for the OTP service.
     */
    final CoreInalogyMultifactorProperties properties;

    /**
     * Secure random number generator for creating secret keys and scratch codes.
     */
    final SecureRandom secureRandom = new SecureRandom();

    /**
     * The length of scratch codes in digits.
     */
    static final int SCRATCH_CODE_LENGTH = 8;

    /**
     * The modulus used to ensure scratch codes have the correct number of digits.
     */
    public static final int SCRATCH_CODE_MODULUS = (int) Math.pow(10, SCRATCH_CODE_LENGTH);

    /**
     * The number of bytes used to generate each scratch code.
     */
    static final int BYTES_PER_SCRATCH_CODE = 4;

    /**
     * Value indicating an invalid scratch code.
     */
    static final int SCRATCH_CODE_INVALID = -1;

    /**
     * Calculates the secret key string representation based on the configured key representation.
     *
     * @param secretKey The raw secret key bytes
     * @return The encoded secret key string (BASE32 or BASE64)
     * @throws IllegalArgumentException If the key representation is unknown
     */
    String calculateSecretKey(byte[] secretKey) {
        return switch (properties.getKeyRepresentation()) {
            case BASE32 -> new Base32().encodeToString(secretKey);
            case BASE64 -> new Base64().encodeToString(secretKey);
        };
    }

    /**
     * Generates a TOTP code for a specific time window.
     *
     * @param secretKey The secret key in raw byte form
     * @return The generated TOTP code as a string
     */
    String generateTOTP(byte[] secretKey) {
        long T = getCurrentInterval();

        StringBuilder steps = new StringBuilder(Long.toHexString(T).toUpperCase());

        // Just get a 16 digit string
        while (steps.length() < 16) {
            steps.insert(0, "0");
        }

        return generateOTP(secretKey, steps.toString(), properties.getCodeDigits(), properties.getHmacHashFunction());
    }

    /**
     * This method generates an OTP value for the given set of parameters.
     *
     * @param key          the shared secret in raw byte form
     * @param counter      a value that reflects a counter or time
     * @param returnDigits number of digits to return
     * @param crypto       the crypto function to use
     * @return A numeric String in base 10 that includes return digits
     */
    private String generateOTP(byte[] key, String counter, int returnDigits, String crypto) {
        // Using the counter
        // First 8 bytes are for the movingFactor
        // Complaint with base RFC 4226 (HOTP)
        StringBuilder counterBuilder = new StringBuilder(counter);
        while (counterBuilder.length() < 16) {
            counterBuilder.insert(0, "0");
        }
        counter = counterBuilder.toString();

        // Get the HEX in a Byte[]
        byte[] msg = hexStr2Bytes(counter);

        // Get the HMAC hash
        byte[] hash = hmac_sha(crypto, key, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        // Calculate the OTP value
        int otp = binary % (int) Math.pow(10, returnDigits);

        // Convert to string with leading zeros if necessary
        StringBuilder result = new StringBuilder(Integer.toString(otp));

        while (result.length() < returnDigits) {
            result.insert(0, "0");
        }

        return result.toString();
    }

    /**
     * Validates a one-time password code against a secret key.
     * Checks the code against a time window to account for clock skew.
     *
     * @param secret The secret key in encoded form
     * @param code   The OTP code to validate
     * @return true if the code is valid, false otherwise
     */
    boolean checkCode(String secret, long code) {
        byte[] decodedKey = decodeSecret(secret);

        // Convert the code to a string with leading zeros if necessary
        StringBuilder codeString = new StringBuilder(Long.toString(code));
        while (codeString.length() < properties.getCodeDigits()) {
            codeString.insert(0, "0");
        }

        long currentInterval = getCurrentInterval();

        for (int i = 0; i <= (properties.getWindowSize() * 2); i++) {
            long delta = clockSkewIndexToDelta(i);
            long adjustedInterval = currentInterval + delta;

            StringBuilder steps = new StringBuilder(Long.toHexString(adjustedInterval).toUpperCase());

            // Just get a 16 digit string
            while (steps.length() < 16) {
                steps.insert(0, "0");
            }

            String candidate = generateOTP(decodedKey, steps.toString(), properties.getCodeDigits(), properties.getHmacHashFunction());

            if (candidate.contentEquals(codeString)) {
                return true;
            }
        }

        return false;
    }

    private long clockSkewIndexToDelta(int idx) {
        return (idx + 1) / 2 * (1 - (idx % 2) * 2);
    }

    /**
     * Generates random bytes for a new secret key.
     *
     * @return A byte array containing the random secret key
     */
    byte[] generateSecretBytes() {
        byte[] secretBytes = new byte[properties.getSecretKeySize() / 8];
        secureRandom.nextBytes(secretBytes);
        return secretBytes;
    }

    /**
     * Decodes an encoded secret key string back to its raw byte representation.
     *
     * @param secret The encoded secret key string
     * @return The decoded secret key as a byte array
     */
    byte[] decodeSecret(String secret) {
        // Decoding the secret key to get its raw byte representation.
        return switch (properties.getKeyRepresentation()) {
            case BASE32 -> {
                Base32 codec32 = new Base32();
                yield codec32.decode(secret.toUpperCase());
            }
            case BASE64 -> {
                Base64 codec64 = new Base64();
                yield codec64.decode(secret);
            }
        };
    }

    /**
     * Generates a list of scratch codes for an account.
     * Scratch codes are backup codes that can be used when the primary
     * authentication method is unavailable.
     *
     * @return A list of scratch codes
     */
    List<Integer> calculateScratchCodes() {
        final List<Integer> scratchCodes = new ArrayList<>();

        for (int i = 0; i < properties.getScratchCodes().getNumber(); ++i) {
            scratchCodes.add(generateScratchCode());
        }

        return scratchCodes;
    }

    /**
     * Generates a single valid scratch code.
     * Continues generating codes until a valid one is found.
     *
     * @return A valid scratch code
     */
    int generateScratchCode() {
        while (true) {
            byte[] scratchCodeBuffer = new byte[BYTES_PER_SCRATCH_CODE];
            secureRandom.nextBytes(scratchCodeBuffer);

            int scratchCode = calculateScratchCode(scratchCodeBuffer);

            if (scratchCode != SCRATCH_CODE_INVALID) {
                return scratchCode;
            }
        }
    }

    /**
     * Calculates a scratch code from random bytes.
     * The code is only valid if it has the correct number of digits.
     *
     * @param scratchCodeBuffer The random bytes to use for generating the scratch code
     * @return The calculated scratch code, or SCRATCH_CODE_INVALID if invalid
     * @throws IllegalArgumentException If the provided buffer is too small
     */
    int calculateScratchCode(byte[] scratchCodeBuffer) {
        if (scratchCodeBuffer.length < BYTES_PER_SCRATCH_CODE) {
            throw new IllegalArgumentException(
                    String.format(
                            "The provided random byte buffer is too small: %d.",
                            scratchCodeBuffer.length));
        }

        int scratchCode = 0;

        for (int i = 0; i < BYTES_PER_SCRATCH_CODE; ++i) {
            scratchCode = (scratchCode << 8) + (scratchCodeBuffer[i] & 0xff);
        }

        scratchCode = (scratchCode & 0x7FFFFFFF) % SCRATCH_CODE_MODULUS;

        // Accept the scratch code only if it has exactly
        // SCRATCH_CODE_LENGTH digits.
        if (validateScratchCode(scratchCode)) {
            return scratchCode;
        } else {
            return SCRATCH_CODE_INVALID;
        }
    }

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hex The hexadecimal string
     * @return The byte array
     */
    private byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        System.arraycopy(bArray, 1, ret, 0, ret.length);
        return ret;
    }

    /**
     * Calculates the HMAC hash of a message using the specified algorithm.
     *
     * @param crypto   The crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
     * @param keyBytes The key bytes
     * @param text     The message to hash
     * @return The HMAC hash
     */
    private byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {
        try {
            Mac hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");

            hmac.init(macKey);

            return hmac.doFinal(text);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Validates that a scratch code has the correct number of digits.
     * A valid scratch code must have exactly SCRATCH_CODE_LENGTH digits.
     *
     * @param scratchCode The scratch code to validate
     * @return true if the scratch code is valid, false otherwise
     */
    boolean validateScratchCode(int scratchCode) {
        return (scratchCode >= SCRATCH_CODE_MODULUS / 10);
    }


    public long getCurrentInterval() {
        Calendar currentCalendar = GregorianCalendar.getInstance(TimeZone.getTimeZone("CEST"));

        return (currentCalendar.getTimeInMillis() / 1000) / properties.getTimeStepSize();

    }
}
