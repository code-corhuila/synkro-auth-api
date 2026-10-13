package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.InitialAdminStore.InitializationAudit;
import co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException;
import co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException.Kind;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The failures a real database makes hard to cause: a refused connection, a statement that fails at a chosen
 * step and, above all, a commit whose confirmation never arrives. No database is involved.
 */
class JdbcInitialAdminStoreFailureTest {

    private static final String SECRET_URL = "jdbc:postgresql://auth_app:very-secret@db.internal:5432/synkro";

    private static final SystemUser ADMIN = new SystemUser("11111111-1111-1111-1111-111111111111", "Ada", "ada@synkro.test",
        "$2a$12$hash", "ADMIN", Instant.parse("2026-01-01T00:00:00Z"), true);
    private static final InitializationAudit AUDIT = new InitializationAudit("22222222-2222-2222-2222-222222222222",
        "operator", Instant.parse("2026-01-01T00:00:00Z"), "corr");

    /** A connection that records what was done to it and fails where told to. */
    private static final class ScriptedConnection {
        final List<String> events = new ArrayList<>();
        Predicate<String> failingSql = sql -> false;
        String failingState = "XX000";
        boolean failCommit;
        boolean adminExists;

        Connection proxy() {
            InvocationHandler handler = (proxy, method, args) -> {
                String name = method.getName();
                events.add(name + (args != null && args.length > 0 && args[0] instanceof String s ? ":" + s : ""));
                switch (name) {
                    case "createStatement":
                        return statement();
                    case "prepareStatement":
                        return prepared((String) args[0]);
                    case "commit":
                        if (failCommit) {
                            throw new SQLException("connection to " + SECRET_URL + " lost", "08006");
                        }
                        return null;
                    default:
                        return defaultOf(method.getReturnType());
                }
            };
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Connection.class}, handler);
        }

        private Statement statement() {
            InvocationHandler handler = (proxy, method, args) -> {
                if (args != null && args.length > 0 && args[0] instanceof String sql) {
                    events.add("sql:" + sql);
                    if (failingSql.test(sql)) {
                        throw new SQLException("failed near " + SECRET_URL, failingState);
                    }
                    if (method.getName().equals("executeQuery")) {
                        return result();
                    }
                }
                return defaultOf(method.getReturnType());
            };
            return (Statement) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Statement.class}, handler);
        }

        private PreparedStatement prepared(String sql) {
            InvocationHandler handler = (proxy, method, args) -> {
                if (method.getName().startsWith("execute")) {
                    events.add("sql:" + sql);
                    if (failingSql.test(sql)) {
                        throw new SQLException("failed near " + SECRET_URL, failingState);
                    }
                    if (method.getName().equals("executeQuery")) {
                        return result();
                    }
                }
                return defaultOf(method.getReturnType());
            };
            return (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {PreparedStatement.class}, handler);
        }

        private ResultSet result() {
            InvocationHandler handler = (proxy, method, args) -> switch (method.getName()) {
                case "next" -> true;
                case "getBoolean" -> adminExists;
                default -> defaultOf(method.getReturnType());
            };
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {ResultSet.class}, handler);
        }

        private static Object defaultOf(Class<?> type) {
            if (type == boolean.class) {
                return false;
            }
            if (type == int.class) {
                return 0;
            }
            if (type == long.class) {
                return 0L;
            }
            return null;
        }

        boolean did(String prefix) {
            return events.stream().anyMatch(e -> e.startsWith(prefix));
        }
    }

    private static JdbcInitialAdminStore storeOver(ScriptedConnection connection) {
        return new JdbcInitialAdminStore(connection::proxy);
    }

    @Test
    void aLostCommitConfirmationIsReportedAsUncertainNeverAsARollback() {
        ScriptedConnection connection = new ScriptedConnection();
        connection.failCommit = true;

        assertThatThrownBy(() -> storeOver(connection).initializeAdministrator(ADMIN, AUDIT))
            .isInstanceOfSatisfying(InitializationFailedException.class, e -> {
                assertThat(e.kind()).isEqualTo(Kind.OUTCOME_UNCERTAIN);
                assertThat(e.sqlState()).isEqualTo("08006");
                assertThat(e.getMessage()).doesNotContain("secret").doesNotContain("db.internal").doesNotContain("rolled back");
                assertThat(e.getCause()).isNull();
            });
        assertThat(connection.did("close")).isTrue();
    }

    @Test
    void aRefusedConnectionIsADatabaseFailureThatDoesNotRepeatTheUrl() {
        JdbcInitialAdminStore store = new JdbcInitialAdminStore(() -> {
            throw new SQLException("Connection to " + SECRET_URL + " refused", "08001");
        });

        assertThatThrownBy(() -> store.initializeAdministrator(ADMIN, AUDIT))
            .isInstanceOfSatisfying(InitializationFailedException.class, e -> {
                assertThat(e.kind()).isEqualTo(Kind.DATABASE);
                assertThat(e.sqlState()).isEqualTo("08001");
                assertThat(e.getMessage()).doesNotContain("secret").doesNotContain("db.internal");
                assertThat(e.getCause()).isNull();
            });
    }

    @Test
    void aLockTimeoutStopsBeforeTheExistenceCheckAndWritesNothing() {
        ScriptedConnection connection = new ScriptedConnection();
        connection.failingSql = sql -> sql.contains("pg_advisory_xact_lock");
        connection.failingState = "55P03";

        assertThatThrownBy(() -> storeOver(connection).initializeAdministrator(ADMIN, AUDIT))
            .isInstanceOfSatisfying(InitializationFailedException.class, e -> assertThat(e.kind()).isEqualTo(Kind.LOCK_TIMEOUT));

        assertThat(connection.did("sql:SELECT EXISTS")).as("no check without the lock").isFalse();
        assertThat(connection.did("prepareStatement")).as("no unlocked insert").isFalse();
        assertThat(connection.did("commit")).isFalse();
        assertThat(connection.did("rollback")).isTrue();
        assertThat(connection.did("close")).isTrue();
    }

    @Test
    void theLockAndTheCheckAreSeparateStatementsInTheAgreedOrder() {
        ScriptedConnection connection = new ScriptedConnection();

        storeOver(connection).initializeAdministrator(ADMIN, AUDIT);

        List<String> sequence = connection.events.stream()
            .filter(e -> e.startsWith("sql:") || e.startsWith("setTransactionIsolation") || e.startsWith("setAutoCommit")
                || e.equals("commit"))
            .toList();
        assertThat(sequence).hasSize(8);
        assertThat(sequence.get(0)).isEqualTo("setAutoCommit");
        assertThat(sequence.get(1)).isEqualTo("setTransactionIsolation");
        assertThat(sequence.get(2)).isEqualTo("sql:SET LOCAL lock_timeout = '10s'");
        assertThat(sequence.get(3)).isEqualTo("sql:SELECT pg_advisory_xact_lock(1398361682::bigint)");
        assertThat(sequence.get(4)).startsWith("sql:SELECT EXISTS");
        assertThat(sequence.get(4)).contains("role = 'ADMIN'").doesNotContain("active").doesNotContain("pg_advisory");
        assertThat(sequence.get(7)).isEqualTo("commit");
    }

    @Test
    void anExistingAdministratorCommitsWithoutWriting() {
        ScriptedConnection connection = new ScriptedConnection();
        connection.adminExists = true;

        assertThat(storeOver(connection).initializeAdministrator(ADMIN, AUDIT).created()).isFalse();

        assertThat(connection.did("prepareStatement")).isFalse();
        assertThat(connection.did("commit")).isTrue();
        assertThat(connection.did("close")).isTrue();
    }

    @Test
    void aFailureWhileWritingRollsBackAndClosesTheConnection() {
        ScriptedConnection connection = new ScriptedConnection();
        connection.failingSql = sql -> sql.contains("user_creation_audit");
        connection.failingState = "23505";

        assertThatThrownBy(() -> storeOver(connection).initializeAdministrator(ADMIN, AUDIT))
            .isInstanceOfSatisfying(InitializationFailedException.class, e -> assertThat(e.sqlState()).isEqualTo("23505"));

        assertThat(connection.did("commit")).isFalse();
        assertThat(connection.did("rollback")).isTrue();
        assertThat(connection.did("close")).isTrue();
    }
}
