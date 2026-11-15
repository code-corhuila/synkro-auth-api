package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionOperations;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository over auth_schema.system_user, auth_schema.refresh_token and auth_schema.password_reset_audit. The audit
 * row (which is also the idempotency record), the new hash and the revocation of the target's refresh tokens are
 * written in one transaction on one connection, started here so the use case stays free of Spring. Rows are never
 * deleted: the service user has no DELETE, and a failed reset is undone by the rollback.
 *
 * Pattern: a transactional repository method, like {@link JdbcUserRegistrationStore}. The adapter owns the boundary
 * and runs the writes inside it, because the use case must orchestrate without ever holding a transaction type, and one
 * method keeps the all-or-nothing guarantee in a single place instead of in the caller's discipline. The revocation is
 * written here, not through {@link JdbcRefreshTokenStore#revokeAllOf(String)}, because that one opens its own
 * transaction (REQUIRES_NEW) and would commit even if this unit later rolled back.
 */
public class JdbcPasswordResetStore implements PasswordResetStore {

    // The receipt is joined only while it is valid, and "valid" is decided here by the database clock: an expired receipt
    // that the cleanup has not deleted yet is as absent as a deleted one. The audit row (the reservation of the key)
    // does not depend on it: the record is found either way.
    private static final String FIND =
        "SELECT a.target_user_id::text, a.occurred_at, r.request_password_hash "
            + "FROM auth_schema.password_reset_audit a "
            + "LEFT JOIN auth_schema.password_reset_receipt r ON r.audit_id = a.audit_id AND r.expires_at > clock_timestamp() "
            + "WHERE a.actor_user_id = ? AND a.idempotency_key = ?";

    // The same bcrypt string that was just written to system_user, kept for 24 hours by the database clock so a manual
    // retry of this request can be recognized without a second bcrypt and without the password or the body.
    private static final String INSERT_RECEIPT =
        "INSERT INTO auth_schema.password_reset_receipt (audit_id, request_password_hash, expires_at) "
            + "VALUES (?, ?, clock_timestamp() + interval '24 hours')";

    // The key is claimed first. A concurrent request of the same actor with the same key waits on the unique index
    // until this transaction ends, then finds the key taken and reads its record, so one of the two executes and the
    // other answers from the record. If a later write fails, the rollback releases the key as well.
    // The content is fixed by the migration (V018): operation and outcome have one value each, and audit_id has no
    // default, so it comes from the attribution.
    private static final String CLAIM_KEY =
        "INSERT INTO auth_schema.password_reset_audit "
            + "(audit_id, operation, actor_user_id, target_user_id, idempotency_key, outcome, occurred_at, correlation_id) "
            + "VALUES (?, 'PASSWORD_RESET', ?, ?, ?, 'SUCCESS', ?, ?) "
            + "ON CONFLICT (actor_user_id, idempotency_key) DO NOTHING";

    // The target's rules are asked again here, in the statement that writes: whatever the use case saw a moment ago,
    // an administrator or an inactive user is never changed.
    private static final String UPDATE_PASSWORD =
        "UPDATE auth_schema.system_user SET password_hash = ? WHERE user_id = ? AND active = true AND role <> 'ADMIN'";

    // The same statement as JdbcRefreshTokenStore.revokeAllOf, on this unit's connection.
    private static final String REVOKE_REFRESH_TOKENS =
        "UPDATE auth_schema.refresh_token SET active = false WHERE user_id = ? AND active = true";

    private static final String TARGET_FOREIGN_KEY = "fk_password_reset_audit_target";

    private final JdbcTemplate jdbc;
    private final TransactionOperations transactions;

    public JdbcPasswordResetStore(JdbcTemplate jdbc, TransactionOperations transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public Optional<Recorded> findByActorAndKey(String actorUserId, String idempotencyKey) {
        return jdbc.query(FIND, (rs, row) -> new Recorded(rs.getString(1), rs.getObject(2, OffsetDateTime.class).toInstant(),
            Optional.ofNullable(rs.getString(3)).map(RequestReceipt::new)), UUID.fromString(actorUserId), idempotencyKey)
            .stream().findFirst();
    }

    @Override
    public Outcome resetPasswordWithAudit(String idempotencyKey, String targetUserId, String newPasswordHash,
                                          ResetAttribution attribution) {
        try {
            return transactions.execute(status -> {
                if (claimKey(idempotencyKey, targetUserId, attribution) == 0) {
                    Recorded original = findByActorAndKey(attribution.actorUserId(), idempotencyKey).orElseThrow(() ->
                        new IllegalStateException("The idempotency key conflicted but its record cannot be read"));
                    return new Outcome.AlreadyRecorded(original);
                }
                // The lock a rotation, a revocation and a login issuance of the same owner take (see OwnerLock): held until
                // the end of this transaction, so none of them can store a credential after the revocation below.
                OwnerLock.acquire(jdbc, targetUserId);
                if (jdbc.update(UPDATE_PASSWORD, newPasswordHash, UUID.fromString(targetUserId)) == 0) {
                    // Nothing to keep: the claim goes with the rollback, so the key is still free for a valid request.
                    status.setRollbackOnly();
                    return new Outcome.TargetNotEligible();
                }
                jdbc.update(REVOKE_REFRESH_TOKENS, UUID.fromString(targetUserId));
                // Last, so that a failure here rolls back the password, the revocation, the audit and the key together.
                jdbc.update(INSERT_RECEIPT, UUID.fromString(attribution.auditId()), newPasswordHash);
                return new Outcome.Reset(attribution.occurredAt());
            });
        } catch (DataIntegrityViolationException e) {
            // A target that is not in system_user fails the foreign key of the claim: it is not eligible either.
            if (violatesTargetForeignKey(e)) {
                return new Outcome.TargetNotEligible();
            }
            throw e;
        }
    }

    private int claimKey(String idempotencyKey, String targetUserId, ResetAttribution attribution) {
        return jdbc.update(CLAIM_KEY, UUID.fromString(attribution.auditId()), UUID.fromString(attribution.actorUserId()),
            UUID.fromString(targetUserId), idempotencyKey,
            OffsetDateTime.ofInstant(attribution.occurredAt(), ZoneOffset.UTC), attribution.correlationId());
    }

    private static boolean violatesTargetForeignKey(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t.getMessage() != null && t.getMessage().contains(TARGET_FOREIGN_KEY)) {
                return true;
            }
        }
        return false;
    }
}
