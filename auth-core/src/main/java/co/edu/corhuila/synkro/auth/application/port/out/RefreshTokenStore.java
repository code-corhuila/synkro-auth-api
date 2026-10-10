package co.edu.corhuila.synkro.auth.application.port.out;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenStore {
    /** The token stops being consumable at expiresAt; the use case decides when that is. */
    void save(String tokenHash, String userId, Instant expiresAt);

    /**
     * Returns the owning userId if the token was valid and unused, and atomically
     * invalidates it in the same call: the "rotation" the story requires. Returns
     * empty for an unknown or already-used token.
     */
    Optional<String> consumeAndRotate(String tokenHash);

    /**
     * Burns the token like {@link #consumeAndRotate} and says what it found: the token was usable
     * ({@link Consumption.Consumed}), it had already been used and has not expired
     * ({@link Consumption.AlreadyUsed}), or nothing usable or replayable exists under that hash
     * ({@link Consumption.Unknown}: never issued, or expired).
     */
    Consumption consume(String tokenHash);

    sealed interface Consumption {
        record Consumed(String userId) implements Consumption {}

        record AlreadyUsed(String userId) implements Consumption {}

        record Unknown() implements Consumption {}
    }
}
