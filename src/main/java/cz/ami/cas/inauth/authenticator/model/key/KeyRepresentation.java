package cz.ami.cas.inauth.authenticator.model.key;

/**
 * Enum representing different encoding formats for authentication keys.
 * 
 * @author Inalogy
 * @since 1.0.0
 */
public enum KeyRepresentation {
    /**
     * Base32 encoding format.
     * Commonly used for TOTP keys in authentication applications.
     */
    BASE32,

    /**
     * Base64 encoding format.
     * An alternative encoding format for authentication keys.
     */
    BASE64
}
