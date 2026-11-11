package co.edu.corhuila.synkro.auth.application.port.out;

import java.time.Instant;
import java.util.Optional;

/**
 * Changes a user's password hash together with the revocation of that user's refresh credentials, the audit record
 * and the idempotency key of the reset, as one unit (HU-AUTH-19, ADR-021).
 *
 * <p>The audit record is the key record: it is scoped to the actor who made the request, so a key can only ever be
 * found by the administrator that used it. Nothing here receives a plaintext password, and nothing returned holds a
 * hash: the use case compares the replayed request against the target's current hash itself.
 */
public interface PasswordResetStore {

    /** What this actor recorded under this key, if anything. A key used by another actor is unknown to this one. */
    Optional<Recorded> findByActorAndKey(String actorUserId, String idempotencyKey);

    /**
     * In one transaction: claims the key for the actor, locks the target's credentials against a rotation in flight,
     * replaces the hash of a target that is still active and not an administrator, and revokes every active refresh
     * credential of that target. The result says which of three things happened, and only {@link Outcome.Reset}
     * keeps any change:
     *
     * <ul>
     *   <li>{@link Outcome.AlreadyRecorded}: this actor already holds the key (a request that won a race), so nothing
     *       was written.</li>
     *   <li>{@link Outcome.TargetNotEligible}: the target is missing, inactive or an administrator at the moment of the
     *       write, so nothing was written and the key was not claimed.</li>
     * </ul>
     *
     * Any other failure propagates and the transaction is rolled back: no key, no audit, no new hash, no revocation.
     *
     * @param newPasswordHash the already hashed password; computed before the call so no lock is held during it
     */
    Outcome resetPasswordWithAudit(String idempotencyKey, String targetUserId, String newPasswordHash,
                                   ResetAttribution attribution);

    /** Who reset the password and when, as the use case knows it. Plain values only: the store decides how they are written. */
    record ResetAttribution(String auditId, String actorUserId, Instant occurredAt, String correlationId) {}

    /** The reset an actor made under a key: the target and when it was committed. */
    record Recorded(String targetUserId, Instant occurredAt) {}

    sealed interface Outcome {
        record Reset(Instant occurredAt) implements Outcome {}

        record AlreadyRecorded(Recorded record) implements Outcome {}

        record TargetNotEligible() implements Outcome {}
    }
}
