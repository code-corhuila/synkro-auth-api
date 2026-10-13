package co.edu.corhuila.synkro.auth.application.port.out;

import java.time.Instant;

public interface RefreshTokenStore {
    /** The token stops being consumable at expiresAt; the use case decides when that is. */
    void save(String tokenHash, String userId, Instant expiresAt);

    /**
     * Burns the token atomically, the "rotation" the story requires, and says what it found: the token
     * was usable ({@link Consumption.Consumed}), it had already been used and has not expired
     * ({@link Consumption.AlreadyUsed}), or nothing usable or replayable exists under that hash
     * ({@link Consumption.Unknown}: never issued, or expired).
     */
    Consumption consume(String tokenHash);

    /**
     * Burns {@code oldTokenHash} and, only if it was usable, stores {@code newTokenHash} for the same owner, as one step
     * that is serialized with {@link #revokeAllOf(String)} of that owner: a revocation either happens before the rotation
     * (the old token is then found already used) or after it (and then it also revokes the replacement). The result means
     * what it means for {@link #consume(String)}; {@link Consumption.Consumed} says the replacement was stored, and nothing
     * is stored for any other result.
     */
    Consumption rotate(String oldTokenHash, String newTokenHash, Instant newExpiresAt);

    /** Makes every refresh token of the user unusable, whether or not it is still active. Nothing is deleted. */
    void revokeAllOf(String userId);

    /**
     * Makes the token unusable if it belongs to {@code ownerId} and is still usable (active, not expired).
     * In every other case, including a token that belongs to someone else, nothing changes and nothing is reported.
     */
    void revoke(String tokenHash, String ownerId);

    sealed interface Consumption {
        record Consumed(String userId) implements Consumption {}

        record AlreadyUsed(String userId) implements Consumption {}

        record Unknown() implements Consumption {}
    }
}
