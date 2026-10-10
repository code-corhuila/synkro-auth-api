package co.edu.corhuila.synkro.auth.application.usecase;

/** Raw input, unchecked: the use case is the single place that validates it. */
public record RegisterUserCommand(String idempotencyKey, String name, String email, String password, String role) {
}
