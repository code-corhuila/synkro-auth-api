package co.edu.corhuila.synkro.auth.application.usecase;

/** Raw input, unchecked: the use case is the single place that validates it. */
public record SearchUsersCommand(String q, String role, Integer page, Integer limit) {
}
