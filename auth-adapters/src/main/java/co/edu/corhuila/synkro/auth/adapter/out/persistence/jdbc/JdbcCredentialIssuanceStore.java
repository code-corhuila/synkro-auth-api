package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.CredentialIssuanceStore;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionOperations;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Persists the refresh credential of a login under the per-owner lock that password reset and refresh rotation take
 * (HU-AUTH-19, ADR-021 Decision 3). One transaction: lock the owner, read the user as it is now, and save the
 * credential only if the user is still active and still holds exactly the hash that login verified. A reset that
 * committed while login was parked on the lock has replaced that hash, so the login is refused and nothing is saved;
 * a reset that waits behind this transaction revokes what it saved.
 *
 * <p>The bcrypt verification happened before this call and is never repeated here: no hashing work runs under the lock.
 * The hash comparison is equality of two stored strings, not a password check, and no hash is logged or put in an error.
 */
public class JdbcCredentialIssuanceStore implements CredentialIssuanceStore {

    private static final String INSERT =
        "INSERT INTO auth_schema.refresh_token (user_id, token, expiration_date) VALUES (?, ?, ?)";

    // Read after the lock is held, so it sees whatever a reset committed while this transaction was waiting
    // (READ COMMITTED takes its snapshot per statement).
    private static final String SELECT_BY_ID =
        "SELECT " + SystemUserRows.COLUMNS + " FROM auth_schema.system_user u WHERE u.user_id = ?";

    private final JdbcTemplate jdbc;
    private final TransactionOperations transactions;

    public JdbcCredentialIssuanceStore(JdbcTemplate jdbc, TransactionOperations transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public Optional<SystemUser> persistRefresh(String userId, String verifiedPasswordHash, String refreshTokenHash, Instant expiresAt) {
        UUID owner;
        try {
            owner = UUID.fromString(userId);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        return transactions.execute(status -> {
            OwnerLock.acquire(jdbc, owner.toString());
            Optional<SystemUser> current = jdbc.query(SELECT_BY_ID, SystemUserRows.TO_USER, owner).stream().findFirst();
            boolean stillValid = current
                .filter(SystemUser::isActive)
                .filter(user -> verifiedPasswordHash != null && verifiedPasswordHash.equals(user.getPasswordHash()))
                .isPresent();
            if (!stillValid) {
                return Optional.<SystemUser>empty();
            }
            jdbc.update(INSERT, owner, refreshTokenHash, Timestamp.from(expiresAt));
            return current;
        });
    }
}
