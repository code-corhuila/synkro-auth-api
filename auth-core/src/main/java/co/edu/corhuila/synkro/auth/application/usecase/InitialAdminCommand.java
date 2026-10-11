package co.edu.corhuila.synkro.auth.application.usecase;

/**
 * Raw input, unchecked: the use case is the single place that validates it. There is no role and no idempotency
 * key: the role is always ADMIN and the lock, not a key, makes a repetition harmless.
 */
public record InitialAdminCommand(String name, String email, String password, String operatorIdentity, String correlationId) {

    /** The input is secret or personal: a stray log of the command must not repeat it. */
    @Override
    public String toString() {
        return "InitialAdminCommand[****]";
    }
}
