package co.edu.corhuila.synkro.auth.application.usecase;

/**
 * {@code userId} is the new administrator's id when {@code created}, and null for the no-op: an existing user is
 * never disclosed.
 */
public record InitialAdminResult(boolean created, String userId) {
}
