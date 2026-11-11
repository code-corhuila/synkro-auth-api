package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * The limits of the password reset request, in one place. The password policy is the registration one; the messages
 * name the field and never repeat a value the caller sent.
 */
final class ResetUserPasswordValidator {
    static final String TARGET = "id";
    static final String IDEMPOTENCY_KEY = IdempotencyKeyRule.FIELD;
    static final String NEW_PASSWORD = "newPassword";
    static final String CONFIRM_PASSWORD = "confirmPassword";

    // Strict on purpose: UUID.fromString accepts "1-1-1-1-1", and the id is copied into a log line when it parses.
    private static final Pattern UUID_TEXT =
        Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private ResetUserPasswordValidator() {}

    static boolean isIdentifier(String id) {
        return id != null && UUID_TEXT.matcher(id).matches();
    }

    static void validate(ResetUserPasswordCommand command) {
        List<Problem> problems = new ArrayList<>();
        if (!isIdentifier(command.targetUserId())) {
            problems.add(new Problem(TARGET, "The path parameter id must be a valid identifier"));
        }
        IdempotencyKeyRule.check(problems, command.idempotencyKey());
        RegisterUserValidator.checkPassword(problems, NEW_PASSWORD, command.newPassword());
        if (!Objects.equals(command.newPassword(), command.confirmPassword())) {
            problems.add(new Problem(CONFIRM_PASSWORD, "The field confirmPassword must match newPassword"));
        }
        if (!problems.isEmpty()) {
            throw new ValidationException(problems);
        }
    }
}
