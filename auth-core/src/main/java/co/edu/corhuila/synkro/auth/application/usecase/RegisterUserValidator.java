package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;
import co.edu.corhuila.synkro.auth.domain.model.Emails;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** The limits of RegisterRequest in synkro-auth-api.yaml and of the system_user checks, in one place. */
final class RegisterUserValidator {
    static final String IDEMPOTENCY_KEY = "Idempotency-Key";

    private static final Pattern EMAIL = Pattern.compile("[^@\\s]+@[^@\\s]+\\.[^@\\s]+");
    // bcrypt reads at most 72 bytes; longer input would be silently truncated or refused by the library.
    private static final int PASSWORD_MAX_BYTES = 72;

    private RegisterUserValidator() {}

    static void validate(RegisterUserCommand command) {
        List<Problem> problems = new ArrayList<>();
        checkKey(problems, command.idempotencyKey());
        checkName(problems, command.name());
        checkEmail(problems, command.email());
        checkPassword(problems, command.password());
        checkRole(problems, command.role());
        if (!problems.isEmpty()) {
            throw new ValidationException(problems);
        }
    }

    private static void checkKey(List<Problem> problems, String key) {
        if (key == null) {
            problems.add(new Problem(IDEMPOTENCY_KEY, "The header Idempotency-Key is required"));
        } else if (key.length() < 8 || key.length() > 128) {
            problems.add(new Problem(IDEMPOTENCY_KEY, "The header Idempotency-Key must have 8 to 128 characters"));
        }
    }

    private static void checkName(List<Problem> problems, String name) {
        if (name == null || name.isBlank()) {
            problems.add(new Problem("name", "The field name is required"));
        } else if (name.length() > 150) {
            problems.add(new Problem("name", "The field name must have at most 150 characters"));
        }
    }

    private static void checkEmail(List<Problem> problems, String email) {
        String normalized = Emails.normalize(email);
        if (normalized == null || normalized.isEmpty()) {
            problems.add(new Problem("email", "The field email is required"));
        } else if (normalized.length() < 3 || normalized.length() > 255) {
            problems.add(new Problem("email", "The field email must have 3 to 255 characters"));
        } else if (!EMAIL.matcher(normalized).matches()) {
            problems.add(new Problem("email", "The field email must be a valid email address"));
        }
    }

    private static void checkPassword(List<Problem> problems, String password) {
        if (password == null || password.isEmpty()) {
            problems.add(new Problem("password", "The field password is required"));
        } else if (password.length() < 8) {
            problems.add(new Problem("password", "The field password must have at least 8 characters"));
        } else if (password.getBytes(StandardCharsets.UTF_8).length > PASSWORD_MAX_BYTES) {
            problems.add(new Problem("password", "The field password must have at most 72 bytes"));
        }
    }

    private static void checkRole(List<Problem> problems, String role) {
        if (role == null || role.isBlank()) {
            problems.add(new Problem("role", "The field role is required"));
        } else if (!SystemUser.isPersonRole(role)) {
            problems.add(new Problem("role", "The field role must be ADMIN, SALESPERSON or INVENTORY"));
        }
    }
}
