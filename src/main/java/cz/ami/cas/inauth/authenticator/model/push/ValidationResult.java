package cz.ami.cas.inauth.authenticator.model.push;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Represents the result of a validation operation.
 * This class encapsulates the success status, HTTP status code, and error message
 * for validation operations in the authentication process.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Getter
public class ValidationResult {
    /**
     * Indicates whether the validation was successful.
     */
    private final boolean success;

    /**
     * The HTTP status code associated with the validation result.
     */
    private final HttpStatus status;

    /**
     * The error message if validation failed, null otherwise.
     */
    private final String errorMessage;

    /**
     * Private constructor to create a validation result.
     *
     * @param success Whether the validation was successful
     * @param status The HTTP status code for the result
     * @param errorMessage The error message if validation failed
     */
    private ValidationResult(boolean success, HttpStatus status, String errorMessage) {
        this.success = success;
        this.status = status;
        this.errorMessage = errorMessage;
    }

    /**
     * Creates a successful validation result.
     *
     * @return A ValidationResult instance with success=true and HTTP status NO_CONTENT
     */
    public static ValidationResult success() {
        return new ValidationResult(true, HttpStatus.NO_CONTENT, null);
    }

    /**
     * Creates a failed validation result with the specified error details.
     *
     * @param status The HTTP status code representing the error
     * @param errorMessage A descriptive error message
     * @return A ValidationResult instance with success=false and the specified error details
     */
    public static ValidationResult error(HttpStatus status, String errorMessage) {
        return new ValidationResult(false, status, errorMessage);
    }
}
