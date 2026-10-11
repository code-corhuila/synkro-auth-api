package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;

import java.util.ArrayList;
import java.util.List;

/**
 * The administrator's data follows the registration rules; the operator identity and the correlation id follow
 * the limits of user_creation_audit (V014). A problem names its field and never repeats a value.
 */
final class InitializeAdminValidator {
    static final int OPERATOR_MAX_CHARACTERS = 200;
    static final int CORRELATION_MAX_CHARACTERS = 128;

    private InitializeAdminValidator() {}

    static void validate(InitialAdminCommand command) {
        if (command == null) {
            throw new ValidationException(List.of(new Problem("command", "The initialization input is required")));
        }
        List<Problem> problems = new ArrayList<>();
        checkText(problems, "operator", command.operatorIdentity(), OPERATOR_MAX_CHARACTERS);
        checkText(problems, "correlationId", command.correlationId(), CORRELATION_MAX_CHARACTERS);
        RegisterUserValidator.checkName(problems, command.name());
        RegisterUserValidator.checkEmail(problems, command.email());
        RegisterUserValidator.checkPassword(problems, command.password());
        if (!problems.isEmpty()) {
            throw new ValidationException(problems);
        }
    }

    // Nonempty, bounded and free of control characters: both values end up in log lines and in an audit record.
    // Length is counted in characters the way PostgreSQL's char_length counts them, not in UTF-16 units.
    private static void checkText(List<Problem> problems, String field, String value, int max) {
        if (value == null || value.isBlank()) {
            problems.add(new Problem(field, "The field " + field + " is required"));
        } else if (value.strip().codePointCount(0, value.strip().length()) > max) {
            problems.add(new Problem(field, "The field " + field + " must have at most " + max + " characters"));
        } else if (value.chars().anyMatch(Character::isISOControl)) {
            problems.add(new Problem(field, "The field " + field + " must not contain control characters"));
        }
    }
}
