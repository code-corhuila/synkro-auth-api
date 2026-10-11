package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.InitialAdminStore;
import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.application.usecase.InitialAdminResult;
import co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException;
import co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException.Kind;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * Creates the first ADMIN and its INITIAL_ADMIN_CREATED audit record under a PostgreSQL advisory lock, on one
 * connection and in one explicit READ COMMITTED transaction. The sequence is fixed:
 *
 * <ol>
 *   <li>begin READ COMMITTED (autocommit off, isolation set before the first statement);</li>
 *   <li>{@code SET LOCAL lock_timeout = '10s'}: local to the transaction, it bounds the wait for the lock;</li>
 *   <li>{@code SELECT pg_advisory_xact_lock(1398361682::bigint)}: waits for any competing initialization;</li>
 *   <li>a <em>separate</em> statement asks whether any user has role ADMIN, active or not;</li>
 *   <li>an ADMIN exists: commit, writing nothing; otherwise insert the user and the audit record, then commit.</li>
 * </ol>
 *
 * The check is a statement of its own on purpose. Under READ COMMITTED every statement takes a new snapshot, so a
 * check that starts after the lock was granted sees what the previous holder committed; a check fused with the
 * lock acquisition would not.
 *
 * Pattern: a transactional repository method over a plain JDBC connection. The adapter owns the boundary, so the
 * use case never sees a Connection or a transaction manager, and the whole protocol lives in one place instead of
 * in the caller's discipline. The accepted tradeoff: the use case cannot compose this with other stores in one
 * transaction, and the adapter rather than the use case enforces "check, then create". It uses its own connection
 * (not the service's pool) because the command runs without the Spring context, and a pool configured with the
 * service's 5 s statement timeout would cut the lock wait short.
 *
 * The lock is transaction-level: commit and rollback release it, and so does a lost connection. It is cooperative,
 * respected only by code that takes the same key, and it is not a durable marker that initialization happened.
 *
 * A failure keeps nothing and never falls back to writing without the lock. If the commit itself fails, the
 * outcome is reported as uncertain, never as rolled back: the server may have committed before the
 * confirmation was lost.
 */
public class JdbcInitialAdminStore implements InitialAdminStore {

    /** Owner Auth, purpose initial administrator creation; reserved in each environment's shared database. */
    public static final long LOCK_KEY = 1398361682L;
    /** How long a transaction waits for the lock before giving up. */
    public static final String LOCK_WAIT = "10s";

    private static final String LOCK_TIMEOUT_STATE = "55P03";
    private static final String UNIQUE_VIOLATION_STATE = "23505";
    private static final String UNIQUE_EMAIL_CONSTRAINT = "uq_system_user_email";

    private static final String SET_LOCK_TIMEOUT = "SET LOCAL lock_timeout = '" + LOCK_WAIT + "'";
    private static final String ACQUIRE_LOCK = "SELECT pg_advisory_xact_lock(" + LOCK_KEY + "::bigint)";
    // No filter on active: a deactivated ADMIN still means the environment was initialized.
    private static final String ADMIN_EXISTS = "SELECT EXISTS (SELECT 1 FROM auth_schema.system_user WHERE role = 'ADMIN')";

    private static final String INSERT_USER =
        "INSERT INTO auth_schema.system_user (user_id, name, email, password_hash, role, registration_date, active) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?)";

    // Content fixed by V014: an initialization is always an operator acting, with no actor user.
    private static final String INSERT_AUDIT =
        "INSERT INTO auth_schema.user_creation_audit "
            + "(audit_id, operation, actor_kind, actor_user_id, operator_identity, created_user_id, outcome, occurred_at, correlation_id) "
            + "VALUES (?, 'INITIAL_ADMIN_CREATED', 'OPERATOR', NULL, ?, ?, 'SUCCESS', ?, ?)";

    /** Opens a new connection as auth_app for each execution. The adapter closes it. */
    @FunctionalInterface
    public interface ConnectionFactory {
        Connection open() throws SQLException;
    }

    /** Test seam: runs on the locked connection once the lock is held and before the existence check. */
    @FunctionalInterface
    interface AfterLock {
        void accept(Connection connection) throws SQLException;
    }

    private final ConnectionFactory connections;
    private final AfterLock afterLock;

    public JdbcInitialAdminStore(ConnectionFactory connections) {
        this(connections, connection -> { });
    }

    JdbcInitialAdminStore(ConnectionFactory connections, AfterLock afterLock) {
        this.connections = connections;
        this.afterLock = afterLock;
    }

    @Override
    public InitialAdminResult initializeAdministrator(SystemUser admin, InitializationAudit audit) {
        Connection connection = open();
        try {
            InitialAdminResult result = work(connection, admin, audit);
            commit(connection);
            return result;
        } finally {
            closeQuietly(connection);
        }
    }

    private Connection open() {
        try {
            return connections.open();
        } catch (SQLException e) {
            throw new InitializationFailedException(Kind.DATABASE, e.getSQLState());
        }
    }

    // Everything up to the commit. Any failure here rolls back, which also releases the lock, and is reported
    // without the driver's message.
    private InitialAdminResult work(Connection connection, SystemUser admin, InitializationAudit audit) {
        try {
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            try (Statement statement = connection.createStatement()) {
                statement.execute(SET_LOCK_TIMEOUT);
                statement.execute(ACQUIRE_LOCK);
            }
            afterLock.accept(connection);
            if (administratorExists(connection)) {
                return new InitialAdminResult(false, null);
            }
            insertUser(connection, admin);
            insertAudit(connection, admin, audit);
            return new InitialAdminResult(true, admin.getUserId());
        } catch (SQLException e) {
            rollbackQuietly(connection);
            throw failure(e);
        } catch (RuntimeException e) {
            rollbackQuietly(connection);
            throw e;
        }
    }

    private static boolean administratorExists(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(ADMIN_EXISTS)) {
            return rows.next() && rows.getBoolean(1);
        }
    }

    private static void insertUser(Connection connection, SystemUser user) throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement(INSERT_USER)) {
            insert.setObject(1, UUID.fromString(user.getUserId()));
            insert.setString(2, user.getName());
            insert.setString(3, user.getEmail());
            insert.setString(4, user.getPasswordHash());
            insert.setString(5, user.getRole());
            insert.setObject(6, OffsetDateTime.ofInstant(user.getRegistrationDate(), ZoneOffset.UTC));
            insert.setBoolean(7, user.isActive());
            insert.executeUpdate();
        } catch (SQLException e) {
            if (UNIQUE_VIOLATION_STATE.equals(e.getSQLState()) && e.getMessage() != null
                && e.getMessage().contains(UNIQUE_EMAIL_CONSTRAINT)) {
                throw new BusinessRuleViolationException("email", "The email is already registered");
            }
            throw e;
        }
    }

    private static void insertAudit(Connection connection, SystemUser user, InitializationAudit audit) throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement(INSERT_AUDIT)) {
            insert.setObject(1, UUID.fromString(audit.auditId()));
            insert.setString(2, audit.operatorIdentity());
            insert.setObject(3, UUID.fromString(user.getUserId()));
            insert.setObject(4, OffsetDateTime.ofInstant(audit.occurredAt(), ZoneOffset.UTC));
            insert.setString(5, audit.correlationId());
            insert.executeUpdate();
        }
    }

    // A commit that throws may or may not have happened on the server, so nothing is said about a rollback; the
    // connection is simply closed, and a later authorized run observes whichever state won.
    private static void commit(Connection connection) {
        try {
            connection.commit();
        } catch (SQLException e) {
            throw new InitializationFailedException(Kind.OUTCOME_UNCERTAIN, e.getSQLState());
        }
    }

    private static RuntimeException failure(SQLException e) {
        if (LOCK_TIMEOUT_STATE.equals(e.getSQLState())) {
            return new InitializationFailedException(Kind.LOCK_TIMEOUT, e.getSQLState());
        }
        return new InitializationFailedException(Kind.DATABASE, e.getSQLState());
    }

    private static void rollbackQuietly(Connection connection) {
        try {
            connection.rollback();
        } catch (SQLException | RuntimeException ignored) {
            // Closing the connection ends the transaction and releases the lock all the same.
        }
    }

    private static void closeQuietly(Connection connection) {
        try {
            connection.close();
        } catch (SQLException | RuntimeException ignored) {
            // Nothing is left to do for a connection that cannot be closed.
        }
    }
}
