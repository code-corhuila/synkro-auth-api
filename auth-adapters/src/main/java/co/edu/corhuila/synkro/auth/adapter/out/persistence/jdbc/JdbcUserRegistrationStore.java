package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore;
import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionOperations;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository over auth_schema.system_user, auth_schema.idempotency_key and auth_schema.user_creation_audit.
 * The user, its key and its audit row are written in one transaction on one connection, started here so the use
 * case stays free of Spring. Rows are never deleted: the service user has no DELETE, and a failed registration
 * is undone by the rollback.
 */
public class JdbcUserRegistrationStore implements UserRegistrationStore {

    private static final String UNIQUE_EMAIL_CONSTRAINT = "uq_system_user_email";
    private static final String KEY_FIELD = "Idempotency-Key";

    private static final String FIND_BY_KEY =
        "SELECT " + SystemUserRows.COLUMNS + " FROM auth_schema.idempotency_key k "
            + "JOIN auth_schema.system_user u ON u.user_id = k.resource_id "
            + "WHERE k.key = ? AND k.resource_type = 'USER'";

    // The key is claimed before the user is written. A concurrent request with the same key waits on
    // the primary key until this transaction ends, then finds the key taken and reads its user, so
    // both answer with a success. If the user insert fails, the rollback releases the key as well.
    private static final String CLAIM_KEY =
        "INSERT INTO auth_schema.idempotency_key (key, resource_type, resource_id) VALUES (?, 'USER', ?) "
            + "ON CONFLICT (key) DO NOTHING";

    private static final String INSERT_USER =
        "INSERT INTO auth_schema.system_user (user_id, name, email, password_hash, role, registration_date, active) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?)";

    // Audit content is fixed by the migration (V014): an ordinary registration is always an ADMIN acting, and the
    // table only ever holds successes. audit_id has no default, so it comes from the attribution.
    private static final String INSERT_AUDIT =
        "INSERT INTO auth_schema.user_creation_audit "
            + "(audit_id, operation, actor_kind, actor_user_id, created_user_id, outcome, occurred_at, correlation_id) "
            + "VALUES (?, 'USER_REGISTERED', 'ADMIN', ?, ?, 'SUCCESS', ?, ?)";

    private final JdbcTemplate jdbc;
    private final TransactionOperations transactions;

    public JdbcUserRegistrationStore(JdbcTemplate jdbc, TransactionOperations transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public Optional<SystemUser> findByIdempotencyKey(String idempotencyKey) {
        return jdbc.query(FIND_BY_KEY, SystemUserRows.TO_USER, idempotencyKey).stream().findFirst();
    }

    @Override
    public Registered registerUserWithAttribution(String idempotencyKey, SystemUser user, CreationAttribution attribution) {
        return transactions.execute(status -> {
            if (jdbc.update(CLAIM_KEY, idempotencyKey, UUID.fromString(user.getUserId())) == 0) {
                SystemUser original = findByIdempotencyKey(idempotencyKey).orElseThrow(() ->
                    new BusinessRuleViolationException(KEY_FIELD, "The Idempotency-Key was already used by another operation"));
                return new Registered(original, false);
            }
            insert(user);
            insertAudit(user, attribution);
            return new Registered(user, true);
        });
    }

    private void insert(SystemUser user) {
        try {
            jdbc.update(INSERT_USER, UUID.fromString(user.getUserId()), user.getName(), user.getEmail(),
                user.getPasswordHash(), user.getRole(),
                OffsetDateTime.ofInstant(user.getRegistrationDate(), ZoneOffset.UTC), user.isActive());
        } catch (DuplicateKeyException e) {
            if (violatesUniqueEmail(e)) {
                throw new BusinessRuleViolationException("email", "The email is already registered");
            }
            throw e;
        }
    }

    private void insertAudit(SystemUser user, CreationAttribution attribution) {
        jdbc.update(INSERT_AUDIT, UUID.fromString(attribution.auditId()), UUID.fromString(attribution.actorUserId()),
            UUID.fromString(user.getUserId()), OffsetDateTime.ofInstant(attribution.occurredAt(), ZoneOffset.UTC),
            attribution.correlationId());
    }

    private static boolean violatesUniqueEmail(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t.getMessage() != null && t.getMessage().contains(UNIQUE_EMAIL_CONSTRAINT)) {
                return true;
            }
        }
        return false;
    }
}
