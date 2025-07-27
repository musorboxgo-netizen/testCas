package cz.ami.cas.inauth.authenticator.model.push;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class ValidationResult {
    private final boolean success;
    private final HttpStatus status;
    private final String errorMessage;

    private ValidationResult(boolean success, HttpStatus status, String errorMessage) {
        this.success = success;
        this.status = status;
        this.errorMessage = errorMessage;
    }

    public static ValidationResult success() {
        return new ValidationResult(true, HttpStatus.NO_CONTENT, null);
    }

    public static ValidationResult error(HttpStatus status, String errorMessage) {
        return new ValidationResult(false, status, errorMessage);
    }
}
