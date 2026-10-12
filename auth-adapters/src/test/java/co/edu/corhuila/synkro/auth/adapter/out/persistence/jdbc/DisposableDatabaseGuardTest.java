package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The initialization tests TRUNCATE auth_schema through the instance administrator. TEST_DATABASE_DISPOSABLE=true
 * and a password say that someone agreed, not which database is on the other end, so the cleanup also needs the
 * database to prove who it is: an exclusive name, compared with current_database() on the administrative
 * connection before anything is emptied.
 *
 * The rule is unit-tested with no database at all. The "refuses and leaves the data" test uses the disposable
 * database of this run, but only with a wrong or missing identity, which is exactly the case that must not delete.
 */
class DisposableDatabaseGuardTest {

    private static final String EXPECTED = "synkro_auth_disposable_ci";

    @Test
    void acceptsTheExclusiveNameWhenTheServerReportsTheSameDatabase() {
        assertThatCode(() -> DisposableDatabaseGuard.requireIdentity(EXPECTED, EXPECTED)).doesNotThrowAnyException();
    }

    @Test
    void refusesWhenTheIdentityIsAbsent() {
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity(null, EXPECTED))
            .isInstanceOf(AssertionError.class).hasMessageContaining(DisposableDatabaseGuard.NAME_VARIABLE);
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity("  ", EXPECTED))
            .isInstanceOf(AssertionError.class).hasMessageContaining(DisposableDatabaseGuard.NAME_VARIABLE);
    }

    @Test
    void refusesANameThatIsNotInTheReservedDisposableNamespace() {
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity("synkro", "synkro"))
            .isInstanceOf(AssertionError.class).hasMessageContaining(DisposableDatabaseGuard.REQUIRED_PREFIX);
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity("postgres", "postgres"))
            .isInstanceOf(AssertionError.class);
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity("synkro_auth_disposable_", "synkro_auth_disposable_"))
            .isInstanceOf(AssertionError.class);
    }

    @Test
    void refusesWhenTheServerReportsAnotherDatabase() {
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity(EXPECTED, "synkro"))
            .isInstanceOf(AssertionError.class).hasMessageContaining("synkro");
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity(EXPECTED, null))
            .isInstanceOf(AssertionError.class);
    }

    @Test
    @EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
    void aMissingOrWrongIdentityPreventsTheCleanupAndKeepsTheRows() throws SQLException {
        InitializationTestDatabase.requireDisposableDatabase();
        String sentinel = "guard-sentinel-" + UUID.randomUUID() + "@synkro.test";
        PostgresTestDatabase.insertUser(PostgresTestDatabase.jdbcTemplate(), "Sentinel", sentinel, "not-a-real-hash", "SALESPERSON", true);
        long before = InitializationTestDatabase.users();

        assertThatThrownBy(() -> InitializationTestDatabase.reset(null)).isInstanceOf(AssertionError.class);
        assertThatThrownBy(() -> InitializationTestDatabase.reset("synkro_auth_disposable_not_this_one"))
            .isInstanceOf(AssertionError.class);
        assertThatThrownBy(() -> InitializationTestDatabase.reset("synkro")).isInstanceOf(AssertionError.class);

        assertThat(InitializationTestDatabase.users()).as("nothing was emptied").isEqualTo(before);
        assertThat(InitializationTestDatabase.count("SELECT count(*) FROM auth_schema.system_user WHERE email = ?", sentinel))
            .isEqualTo(1);
    }

    @Test
    @EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
    void theServerReportedNameIsTheOneComparedNotTheOneInTheUrl() throws SQLException {
        InitializationTestDatabase.requireDisposableDatabase();
        try (Connection admin = InitializationTestDatabase.adminConnection()) {
            assertThatCode(() -> DisposableDatabaseGuard.requireDatabase(admin, System.getenv(DisposableDatabaseGuard.NAME_VARIABLE)))
                .doesNotThrowAnyException();
            assertThatThrownBy(() -> DisposableDatabaseGuard.requireDatabase(admin, "synkro_auth_disposable_other"))
                .isInstanceOf(AssertionError.class);
        }
    }
}
