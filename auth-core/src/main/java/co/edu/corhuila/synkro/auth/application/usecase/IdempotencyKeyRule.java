package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;

import java.util.List;

/** The Idempotency-Key header of _shared.yaml, checked the same way by every creation. */
final class IdempotencyKeyRule {
    static final String FIELD = "Idempotency-Key";

    private IdempotencyKeyRule() {}

    static void check(List<Problem> problems, String key) {
        if (key == null) {
            problems.add(new Problem(FIELD, "The header Idempotency-Key is required"));
        } else if (key.length() < 8 || key.length() > 128) {
            problems.add(new Problem(FIELD, "The header Idempotency-Key must have 8 to 128 characters"));
        }
    }
}
