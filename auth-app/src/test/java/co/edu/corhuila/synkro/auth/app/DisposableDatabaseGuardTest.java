package co.edu.corhuila.synkro.auth.app;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The same rule as the adapters module's DisposableDatabaseGuardTest, for the cleanup in
 * InitialAdminCliIntegrationTest (the modules share no test sources). No database is involved.
 */
class DisposableDatabaseGuardTest {

    private static final String EXPECTED = "synkro_auth_disposable_ci";

    @Test
    void acceptsTheExclusiveNameWhenTheServerReportsTheSameDatabase() {
        assertThatCode(() -> DisposableDatabaseGuard.requireIdentity(EXPECTED, EXPECTED)).doesNotThrowAnyException();
    }

    @Test
    void refusesWhenTheIdentityIsAbsentOrBlank() {
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity(null, EXPECTED)).isInstanceOf(AssertionError.class)
            .hasMessageContaining(DisposableDatabaseGuard.NAME_VARIABLE);
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity(" ", EXPECTED)).isInstanceOf(AssertionError.class);
    }

    @Test
    void refusesANameOutsideTheReservedNamespace() {
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity("synkro", "synkro")).isInstanceOf(AssertionError.class);
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity("postgres", "postgres")).isInstanceOf(AssertionError.class);
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity("synkro_auth_disposable_", "synkro_auth_disposable_"))
            .isInstanceOf(AssertionError.class);
    }

    @Test
    void refusesWhenTheServerReportsAnotherDatabase() {
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity(EXPECTED, "synkro")).isInstanceOf(AssertionError.class);
        assertThatThrownBy(() -> DisposableDatabaseGuard.requireIdentity(EXPECTED, null)).isInstanceOf(AssertionError.class);
    }
}
