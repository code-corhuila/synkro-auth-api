package co.edu.corhuila.synkro.auth.application.port.out;

import co.edu.corhuila.synkro.auth.application.usecase.InitialAdminResult;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Instant;

/**
 * Creates the first administrator of an environment together with the record of who initialized it, as one
 * unit that is serialized against every other initialization of the same database.
 */
public interface InitialAdminStore {

    /**
     * Under a lock shared by every execution against the same database, creates the user and its
     * INITIAL_ADMIN_CREATED audit record in one transaction, unless an ADMIN already exists (active or not), in
     * which case nothing is written and the result is not {@code created}. A failure keeps nothing; it never
     * falls back to writing without the lock.
     *
     * @throws co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException
     *         when the lock cannot be obtained in time, the database fails, or the commit cannot be confirmed
     * @throws co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException
     *         naming {@code email} when the email already belongs to a user who is not an ADMIN
     */
    InitialAdminResult initializeAdministrator(SystemUser admin, InitializationAudit audit);

    /** Who ran the initialization and when, as the use case knows it. Plain values only: the store decides how they are written. */
    record InitializationAudit(String auditId, String operatorIdentity, Instant occurredAt, String correlationId) {}
}
