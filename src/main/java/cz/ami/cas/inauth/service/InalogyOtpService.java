package cz.ami.cas.inauth.service;

import com.warrenstrange.googleauth.GoogleAuthenticatorException;
import cz.ami.cas.inauth.authenticator.model.key.InalogyAuthenticatorKey;
import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;

@RequiredArgsConstructor
@Slf4j
public class InalogyOtpService {
    final CoreInalogyMultifactorProperties properties;
    final SecureRandom secureRandom = new SecureRandom();

    static final int SCRATCH_CODE_LENGTH = 8;
    public static final int SCRATCH_CODE_MODULUS = (int) Math.pow(10, SCRATCH_CODE_LENGTH);
    static final int BYTES_PER_SCRATCH_CODE = 4;
    static final int SCRATCH_CODE_INVALID = -1;

    String calculateSecretKey(byte[] secretKey)
    {
        return switch (properties.getKeyRepresentation()) {
            case BASE32 -> new Base32().encodeToString(secretKey);
            case BASE64 -> new Base64().encodeToString(secretKey);
            default -> throw new IllegalArgumentException("Unknown key representation type.");
        };
    }

    boolean checkCode(
            String secret,
            long code,
            long timestamp)
    {
        byte[] decodedKey = decodeSecret(secret);

        // convert unix time into a 30 second "window" as specified by the
        // TOTP specification. Using Google's default interval of 30 seconds.
        final long timeWindow = getTimeWindowFromTime(timestamp);

        final int window = properties.getWindowSize();

        // Calculating the verification code of the given key in each of the
        // time intervals and returning true if the provided code is equal to
        // one of them.
        for (int i = -((window - 1) / 2); i <= window / 2; ++i)
        {
            // Calculating the verification code for the current time interval.
            long hash = calculateCode(decodedKey, timeWindow + i);

            // Checking if the provided code is equal to the calculated one.
            if (hash == code)
            {
                // The verification code is valid.
                return true;
            }
        }

        // The verification code is invalid.
        return false;
//        return code == 123456;
    }

    byte[] generateSecretBytes()
    {
        byte[] secretBytes = new byte[properties.getSecretKeySize() / 8];
        secureRandom.nextBytes(secretBytes);
        return secretBytes;
    }

    byte[] decodeSecret(String secret)
    {
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

    int calculateCode(byte[] key, long tm)
    {
        // Allocating an array of bytes to represent the specified instant
        // of time.
        byte[] data = new byte[8];
        long value = tm;

        // Converting the instant of time from the long representation to a
        // big-endian array of bytes (RFC4226, 5.2. Description).
        for (int i = 8; i-- > 0; value >>>= 8)
        {
            data[i] = (byte) value;
        }

        // Building the secret key specification for the HmacSHA1 algorithm.
        SecretKeySpec signKey = new SecretKeySpec(key, properties.getHmacHashFunction());

        try
        {
            // Getting an HmacSHA1/HmacSHA256 algorithm implementation from the JCE.
            Mac mac = Mac.getInstance(properties.getHmacHashFunction());

            // Initializing the MAC algorithm.
            mac.init(signKey);

            // Processing the instant of time and getting the encrypted data.
            byte[] hash = mac.doFinal(data);

            // Building the validation code performing dynamic truncation
            // (RFC4226, 5.3. Generating an HOTP value)
            int offset = hash[hash.length - 1] & 0xF;

            // We are using a long because Java hasn't got an unsigned integer type
            // and we need 32 unsigned bits).
            long truncatedHash = 0;

            for (int i = 0; i < 4; ++i)
            {
                truncatedHash <<= 8;

                // Java bytes are signed but we need an unsigned integer:
                // cleaning off all but the LSB.
                truncatedHash |= (hash[offset + i] & 0xFF);
            }

            // Clean bits higher than the 32nd (inclusive) and calculate the
            // module with the maximum validation code value.
            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= properties.getKeyModulus();

            // Returning the validation code to the caller.
            return (int) truncatedHash;
        }
        catch (NoSuchAlgorithmException | InvalidKeyException ex)
        {
            // Logging the exception.
            LOGGER.error(ex.getMessage(), ex, Level.SEVERE);

            // We're not disclosing internal error details to our clients.
            throw new GoogleAuthenticatorException("The operation cannot be performed now.");
        }
    }

    long getTimeWindowFromTime(long time)
    {
        return time / this.properties.getTimeStepSize();
    }



    int calculateValidationCode(byte[] secretKey)
    {
        return calculateCode(secretKey, 0);
    }

    List<Integer> calculateScratchCodes()
    {
        final List<Integer> scratchCodes = new ArrayList<>();

        for (int i = 0; i < properties.getScratchCodes().getNumber(); ++i)
        {
            scratchCodes.add(generateScratchCode());
        }

        return scratchCodes;
    }

    int generateScratchCode()
    {
        while (true)
        {
            byte[] scratchCodeBuffer = new byte[BYTES_PER_SCRATCH_CODE];
            secureRandom.nextBytes(scratchCodeBuffer);

            int scratchCode = calculateScratchCode(scratchCodeBuffer);

            if (scratchCode != SCRATCH_CODE_INVALID)
            {
                return scratchCode;
            }
        }
    }

    int calculateScratchCode(byte[] scratchCodeBuffer)
    {
        if (scratchCodeBuffer.length < BYTES_PER_SCRATCH_CODE)
        {
            throw new IllegalArgumentException(
                    String.format(
                            "The provided random byte buffer is too small: %d.",
                            scratchCodeBuffer.length));
        }

        int scratchCode = 0;

        for (int i = 0; i < BYTES_PER_SCRATCH_CODE; ++i)
        {
            scratchCode = (scratchCode << 8) + (scratchCodeBuffer[i] & 0xff);
        }

        scratchCode = (scratchCode & 0x7FFFFFFF) % SCRATCH_CODE_MODULUS;

        // Accept the scratch code only if it has exactly
        // SCRATCH_CODE_LENGTH digits.
        if (validateScratchCode(scratchCode))
        {
            return scratchCode;
        }
        else
        {
            return SCRATCH_CODE_INVALID;
        }
    }

    boolean validateScratchCode(int scratchCode)
    {
        return (scratchCode >= SCRATCH_CODE_MODULUS / 10);
    }
}
