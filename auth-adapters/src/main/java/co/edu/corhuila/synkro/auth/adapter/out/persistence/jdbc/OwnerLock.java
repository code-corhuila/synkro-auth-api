package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import org.springframework.jdbc.core.JdbcTemplate;

import java.util.UUID;

/**
 * The per-owner transaction lock that password reset, credential issuance at login and refresh rotation all take
 * (ADR-021 Decision 3). One place defines the key space and the canonical identity (the lower-case text of the user id,
 * whatever case came in), so the three operations can never end up serializing on different keys.
 *
 * <p>It is a transaction-scoped advisory lock: it is held until the end of the transaction that took it and there is
 * nothing to release. Lock order, to rule out deadlocks between the three: rotation and issuance take this lock first
 * and only read or insert rows afterwards; a reset claims its audit row first (an insert that waits for no other
 * transaction's owner lock) and takes this lock before it updates the user and the refresh rows. No operation takes
 * two owner locks, and none waits for a row lock held by one that waits for this lock.
 */
final class OwnerLock {

    private static final String LOCK_OWNER = "SELECT count(*) FROM (SELECT pg_advisory_xact_lock(?, hashtext(?))) locked";

    private OwnerLock() {}

    /** Takes the lock inside the transaction that is current on {@code jdbc}'s connection. */
    static void acquire(JdbcTemplate jdbc, String userId) {
        jdbc.queryForObject(LOCK_OWNER, Long.class, JdbcRefreshTokenStore.LOCK_NAMESPACE, UUID.fromString(userId).toString());
    }
}
