package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository over auth_schema.refresh_token. The token column holds the hash the use case
 * hands over, never the token. Rows are never deleted: the service user has no DELETE.
 */
public class JdbcRefreshTokenStore implements RefreshTokenStore {

    private static final String INSERT =
        "INSERT INTO auth_schema.refresh_token (user_id, token, expiration_date) VALUES (?, ?, ?)";

    // One statement decides "usable or not" and burns the token, so two concurrent callers
    // cannot both win: the second waits on the row lock, re-evaluates active = true against
    // the committed row and finds nothing.
    private static final String CONSUME =
        "UPDATE auth_schema.refresh_token SET active = false "
            + "WHERE token = ? AND active = true AND expiration_date > now() "
            + "RETURNING user_id::text";

    // Asked only after CONSUME found nothing. By then the winner of a race has committed, so an
    // inactive, unexpired row is a token that was used before: a replay.
    private static final String FIND_USED =
        "SELECT user_id::text FROM auth_schema.refresh_token "
            + "WHERE token = ? AND active = false AND expiration_date > now()";

    // Only the active rows change, and only this user's: nothing is deleted (auth_app has no DELETE).
    private static final String REVOKE_ALL_OF_USER =
        "UPDATE auth_schema.refresh_token SET active = false WHERE user_id = ? AND active = true";

    // The owner is part of the condition, so another user's token is simply not found. It is compared as text:
    // a subject that is not a UUID matches nothing instead of failing. An expired token is left as it is.
    private static final String REVOKE_OF_OWNER =
        "UPDATE auth_schema.refresh_token SET active = false "
            + "WHERE token = ? AND user_id::text = ? AND active = true AND expiration_date > now()";

    // Who owns the token, whatever its state: read first only to know which owner to serialize with.
    private static final String OWNER_OF = "SELECT user_id::text FROM auth_schema.refresh_token WHERE token = ?";

    // Held until the end of the transaction. A rotation and a revocation of the same owner take it before they touch
    // any row, so a revocation cannot run between the burning of a token and the storing of its replacement. The
    // two-integer form is a different key space from the bigint key that ADR-014 reserves for the initial administrator.
    private static final String LOCK_OWNER = "SELECT count(*) FROM (SELECT pg_advisory_xact_lock(?, hashtext(?))) locked";
    static final int LOCK_NAMESPACE = 0x52544F4B;

    private final JdbcTemplate jdbc;
    private final TransactionOperations independentTransaction;

    public JdbcRefreshTokenStore(JdbcTemplate jdbc, PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.independentTransaction = template;
    }

    @Override
    public void save(String tokenHash, String userId, Instant expiresAt) {
        jdbc.update(INSERT, UUID.fromString(userId), tokenHash, Timestamp.from(expiresAt));
    }

    @Override
    public Consumption consume(String tokenHash) {
        return firstOwner(CONSUME, tokenHash).<Consumption>map(Consumption.Consumed::new)
            .or(() -> firstOwner(FIND_USED, tokenHash).map(Consumption.AlreadyUsed::new))
            .orElseGet(Consumption.Unknown::new);
    }

    // Burning the old token and storing its replacement are one transaction, serialized per owner with revokeAllOf.
    // A revocation that wins the lock has already made the old token "used", which this reports as a replay.
    @Override
    public Consumption rotate(String oldTokenHash, String newTokenHash, Instant newExpiresAt) {
        Optional<String> owner = firstOwner(OWNER_OF, oldTokenHash);
        if (owner.isEmpty()) {
            return new Consumption.Unknown();
        }
        return independentTransaction.execute(status -> {
            lockOwner(owner.get());
            Consumption result = consume(oldTokenHash);
            if (result instanceof Consumption.Consumed consumed) {
                save(newTokenHash, consumed.userId(), newExpiresAt);
            }
            return result;
        });
    }

    // Its own transaction (REQUIRES_NEW): the request that detects a reuse answers 401, and whatever
    // transaction that call runs in must not take the revocation down with it. It waits for a rotation of the same
    // owner that is in progress, so the replacement that rotation stores is revoked with the rest.
    @Override
    public void revokeAllOf(String userId) {
        independentTransaction.executeWithoutResult(status -> {
            lockOwner(userId);
            jdbc.update(REVOKE_ALL_OF_USER, UUID.fromString(userId));
        });
    }

    private void lockOwner(String userId) {
        jdbc.queryForObject(LOCK_OWNER, Long.class, LOCK_NAMESPACE, userId);
    }

    @Override
    public void revoke(String tokenHash, String ownerId) {
        jdbc.update(REVOKE_OF_OWNER, tokenHash, ownerId);
    }

    private Optional<String> firstOwner(String sql, String tokenHash) {
        return jdbc.queryForList(sql, String.class, tokenHash).stream().findFirst();
    }
}
