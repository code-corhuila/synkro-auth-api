package co.edu.corhuila.synkro.auth.application.port.out;

import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.util.Optional;

/** Saves a user together with the idempotency key that protects its creation, as one unit. */
public interface UserRegistrationStore {

    /** The user that the key created, if the key was already used. */
    Optional<SystemUser> findByIdempotencyKey(String idempotencyKey);

    /**
     * Saves the user and claims the key in one transaction: both are kept or neither is. If another
     * request already holds the key, nothing is kept and that request's user is returned with
     * {@code created = false}.
     *
     * @throws co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException
     *         naming {@code email} when the email already belongs to another user
     */
    Registered registerOnce(String idempotencyKey, SystemUser user);

    record Registered(SystemUser user, boolean created) {}
}
