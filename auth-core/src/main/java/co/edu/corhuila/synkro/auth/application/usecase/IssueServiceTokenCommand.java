package co.edu.corhuila.synkro.auth.application.usecase;

/** Raw input, unchecked: the use case is the single place that validates it. The permissions are not input. */
public record IssueServiceTokenCommand(String idempotencyKey, String service) {
}
