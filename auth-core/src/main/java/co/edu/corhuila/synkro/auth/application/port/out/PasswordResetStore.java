package co.edu.corhuila.synkro.auth.application.port.out;

import java.time.Instant;
import java.util.Optional;

/**
 * Changes a user's password hash together with the revocation of that user's refresh credentials, the audit record
 * and the idempotency key of the reset, as one unit (HU-AUTH-19, ADR-021).
 *
 * <p>The audit record is the key record: it is scoped to the actor who made the request, so a key can only ever be
 * found by the administrator that used it, and it is permanent: nothing that expires or is cleaned up frees a key.
 * Nothing here receives a plaintext password. The only hash that comes back is the one in the private
 * {@link RequestReceipt} of that same reset, valid for 24 hours: the use case compares a replayed request against it,
 * never against the target's current hash.
 */
public interface PasswordResetStore {

    /** What this actor recorded under this key, if anything. A key used by another actor is unknown to this one. */
    Optional<Recorded> findByActorAndKey(String actorUserId, String idempotencyKey);

    /**
     * In one transaction: claims the key for the actor, takes the target's owner lock (the one a rotation and a login
     * issuance also take), replaces the hash of a target that is still active and not an administrator, revokes every
     * active refresh credential of that target and stores the receipt (the same hash, 24 hours by the database clock).
     * The result says which of three things happened, and only {@link Outcome.Reset} keeps any change:
     *
     * <ul>
     *   <li>{@link Outcome.AlreadyRecorded}: this actor already holds the key (a request that won a race), so nothing
     *       was written.</li>
     *   <li>{@link Outcome.TargetNotEligible}: the target is missing, inactive or an administrator at the moment of the
     *       write, so nothing was written and the key was not claimed.</li>
     * </ul>
     *
     * Any other failure, the receipt's included, propagates and the transaction is rolled back: no key, no audit, no
     * new hash, no revocation, no receipt.
     *
     * @param newPasswordHash the already hashed password; computed before the call so no lock is held during it
     */
    Outcome resetPasswordWithAudit(String idempotencyKey, String targetUserId, String newPasswordHash,
                                   ResetAttribution attribution);

    /** Who reset the password and when, as the use case knows it. Plain values only: the store decides how they are written. */
    record ResetAttribution(String auditId, String actorUserId, Instant occurredAt, String correlationId) {}

    /**
     * The reset an actor made under a key: the target, when it was committed and, while it is still valid by the
     * database clock, the private receipt of the original request. An expired or removed receipt is simply absent:
     * the key stays recorded and consumed, but the request can no longer be recognised.
     */
    record Recorded(String targetUserId, Instant occurredAt, Optional<RequestReceipt> receipt) {}

    /**
     * The bcrypt string that was computed for the original request and assigned to the user in the same transaction
     * (ADR-021 Decision 5). It is credential material of a possibly retired password: it only ever goes to
     * {@code PasswordHasher.matches}, and it never appears in a message, a log or a {@code toString}.
     */
    record RequestReceipt(String passwordHash) {
        @Override
        public String toString() {
            return "RequestReceipt[passwordHash=<redacted>]";
        }
    }

    sealed interface Outcome {
        record Reset(Instant occurredAt) implements Outcome {}

        record AlreadyRecorded(Recorded record) implements Outcome {}

        record TargetNotEligible() implements Outcome {}
    }
}
