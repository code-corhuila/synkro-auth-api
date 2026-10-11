package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Initialization is only observable on a database with no ADMIN, and auth_app cannot delete rows, so these tests
 * empty auth_schema through the instance administrator first. That is destructive, so it needs an explicit
 * opt-in (TEST_DATABASE_DISPOSABLE=true) and credentials that exist only for the disposable database; a
 * missing opt-in fails the test, it never silently skips it.
 *
 * Everything else runs as auth_app, exactly like the command does.
 */
final class InitializationTestDatabase {

    static final String DISPOSABLE_VARIABLE = "TEST_DATABASE_DISPOSABLE";
    static final String ADMIN_USER_VARIABLE = "TEST_ADMIN_DATABASE_USER";
    static final String ADMIN_PASSWORD_VARIABLE = "TEST_ADMIN_DATABASE_PASSWORD";
    static final long LOCK_KEY = 1398361682L;

    private InitializationTestDatabase() {}

    static void requireDisposableDatabase() {
        assertThat(System.getenv(DISPOSABLE_VARIABLE))
            .as(DISPOSABLE_VARIABLE + " must be 'true': the initialization tests empty auth_schema")
            .isEqualTo("true");
        assertThat(System.getenv(ADMIN_PASSWORD_VARIABLE))
            .as(ADMIN_PASSWORD_VARIABLE + " must be set for the disposable database").isNotBlank();
    }

    /** The connection the command uses: auth_app, never the administrator. */
    static Connection appConnection() throws SQLException {
        return DriverManager.getConnection(System.getenv(PostgresTestDatabase.URL_VARIABLE),
            System.getenv().getOrDefault("TEST_DATABASE_USER", "auth_app"), System.getenv("TEST_DATABASE_PASSWORD"));
    }

    static JdbcInitialAdminStore.ConnectionFactory appConnections() {
        return InitializationTestDatabase::appConnection;
    }

    static Connection adminConnection() throws SQLException {
        return DriverManager.getConnection(System.getenv(PostgresTestDatabase.URL_VARIABLE),
            System.getenv().getOrDefault(ADMIN_USER_VARIABLE, "postgres"), System.getenv(ADMIN_PASSWORD_VARIABLE));
    }

    static void reset() throws SQLException {
        requireDisposableDatabase();
        try (Connection c = adminConnection(); Statement s = c.createStatement()) {
            s.execute("TRUNCATE auth_schema.user_creation_audit, auth_schema.refresh_token, "
                + "auth_schema.service_token, auth_schema.idempotency_key, auth_schema.system_user CASCADE");
        }
    }

    static long count(String sql, Object... parameters) throws SQLException {
        try (Connection c = appConnection(); PreparedStatement s = c.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                s.setObject(i + 1, parameters[i]);
            }
            try (ResultSet rs = s.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    static String text(String sql, Object... parameters) throws SQLException {
        try (Connection c = appConnection(); PreparedStatement s = c.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                s.setObject(i + 1, parameters[i]);
            }
            try (ResultSet rs = s.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    static long admins() throws SQLException {
        return count("SELECT count(*) FROM auth_schema.system_user WHERE role = 'ADMIN'");
    }

    static long users() throws SQLException {
        return count("SELECT count(*) FROM auth_schema.system_user");
    }

    static long initializationAudits() throws SQLException {
        return count("SELECT count(*) FROM auth_schema.user_creation_audit WHERE operation = 'INITIAL_ADMIN_CREATED'");
    }

    static long audits() throws SQLException {
        return count("SELECT count(*) FROM auth_schema.user_creation_audit");
    }

    /** Sessions waiting for, or holding, the reserved advisory lock (single-bigint form: classid 0, objsubid 1). */
    static long lockEntries(boolean granted) throws SQLException {
        return count("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid::bigint = 0 AND objid::bigint = ? "
            + "AND objsubid = 1 AND granted = ?", LOCK_KEY, granted);
    }
}
