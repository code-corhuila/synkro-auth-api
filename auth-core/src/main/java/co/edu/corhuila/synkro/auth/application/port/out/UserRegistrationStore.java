package co.edu.corhuila.synkro.auth.application.port.out;

import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Instant;
import java.util.Optional;

/**
 * Saves a user together with the idempotency key that protects its creation and the record of who created
 * it, as one unit.
 */
public interface UserRegistrationStore {

    /** The user that the key created, if the key was already used. */
    Optional<SystemUser> findByIdempotencyKey(String idempotencyKey);

    /**
     * Saves the user, claims the key and records the attribution in one transaction: all three are kept or
     * none is. If another request already holds the key, nothing is kept and that request's user is
     * returned with {@code created = false}.
     *
     * @throws co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException
     *         naming {@code email} when the email already belongs to another user
     */
    Registered registerUserWithAttribution(String idempotencyKey, SystemUser user, CreationAttribution attribution);

    /**
     * Who created a user and when, as the use case knows it. Plain values only: the store decides how they are
     * written.
     */
    record CreationAttribution(String auditId, String actorUserId, Instant occurredAt, String correlationId) {}

    record Registered(SystemUser user, boolean created) {}
}
