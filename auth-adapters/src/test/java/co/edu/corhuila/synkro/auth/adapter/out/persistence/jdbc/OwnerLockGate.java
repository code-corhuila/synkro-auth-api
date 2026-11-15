package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

/**
 * Orders concurrent work on real PostgreSQL without sleeping to "let something happen first".
 *
 * <p>The gate holds the per-owner advisory lock that password reset, login issuance and refresh rotation all take.
 * Work started while it is held queues on that lock, and PostgreSQL grants a contended lock to its waiters in the order
 * they began to wait. {@link #awaitWaiters} blocks until the database itself reports that many sessions waiting
 * ({@code pg_locks}), so a test starts the second operation only once the first one is parked behind the gate, and
 * releases the gate to let them run in exactly that order. Polling a condition is not a timing assumption about the
 * order: the order is the lock queue.
 */
final class OwnerLockGate implements AutoCloseable {

    private static final long TIMEOUT_MILLIS = 30_000;

    private final String ownerId;
    private final Connection holder;
    private boolean released;

    OwnerLockGate(String ownerId) throws SQLException {
        this.ownerId = UUID.fromString(ownerId).toString();
        this.holder = InitializationTestDatabase.appConnection();
        holder.setAutoCommit(false);
        try (PreparedStatement s = holder.prepareStatement("SELECT pg_advisory_xact_lock(?, hashtext(?))")) {
            s.setInt(1, JdbcRefreshTokenStore.LOCK_NAMESPACE);
            s.setString(2, this.ownerId);
            s.execute();
        }
    }

    /** Lets the queued operations go, first come first served. */
    void release() throws SQLException {
        if (!released) {
            released = true;
            holder.commit();
            holder.close();
        }
    }

    /** Sessions of the database that wait for this owner's lock right now. */
    long waiters() throws SQLException {
        try (Connection c = InitializationTestDatabase.appConnection();
             PreparedStatement s = c.prepareStatement(
                 "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objsubid = 2 AND NOT granted "
                     + "AND classid::bigint = ? AND objid::bigint = (hashtext(?)::bigint & 4294967295)")) {
            s.setLong(1, JdbcRefreshTokenStore.LOCK_NAMESPACE);
            s.setString(2, ownerId);
            try (ResultSet rs = s.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    /** Waits until exactly {@code expected} sessions are parked behind the gate, or fails after a generous bound. */
    void awaitWaiters(long expected) throws SQLException, InterruptedException {
        long deadline = System.currentTimeMillis() + TIMEOUT_MILLIS;
        long seen = waiters();
        while (seen != expected) {
            if (System.currentTimeMillis() > deadline) {
                throw new AssertionError("expected " + expected + " sessions waiting for the owner lock but saw " + seen);
            }
            Thread.onSpinWait();
            Thread.sleep(5); // a poll interval, not an ordering assumption: the lock queue orders the work
            seen = waiters();
        }
    }

    @Override
    public void close() throws SQLException {
        if (!released) {
            released = true;
            holder.rollback();
            holder.close();
        }
    }
}
