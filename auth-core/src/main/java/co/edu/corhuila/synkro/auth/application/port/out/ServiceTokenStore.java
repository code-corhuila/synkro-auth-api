package co.edu.corhuila.synkro.auth.application.port.out;

import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;

import java.util.Optional;

/** Saves the metadata of a service token together with the idempotency key that protects its issuance, as one unit. */
public interface ServiceTokenStore {

    /** The token that the key issued, if the key was already used to issue one. */
    Optional<ServiceToken> findByIdempotencyKey(String idempotencyKey);

    /**
     * Saves the metadata and claims the key in one transaction: both are kept or neither is. If another
     * request already holds the key, nothing is kept and that request's token is returned with
     * {@code created = false}.
     *
     * @throws co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException
     *         naming {@code Idempotency-Key} when the key already belongs to another kind of resource
     */
    Issued issueOnce(String idempotencyKey, ServiceToken token);

    record Issued(ServiceToken token, boolean created) {}
}
